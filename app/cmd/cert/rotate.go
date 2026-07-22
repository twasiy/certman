// Copyright 2026 Tassok Imam Wasiy

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cert

import (
	"certman/app/domain"
	"certman/app/utils"
	_db_ "certman/db"
	"certman/db/base"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"time"
)

type RotateCmd struct {
	ID       int64 `arg:"" help:"Database ID of the certificate to rotate."`
	IssuerID int64 `name:"iss" help:"Database ID of the issuing parent certificate (optional for self-signed Root CAs)."`
	KeyID    int64 `name:"kid" required:"" help:"Database ID of the new key pair to sign the rotated certificate."`
}

func (rc *RotateCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	dbCert, err := query.GetCertificateByID(ctx, rc.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch certificate from DB: %w", err)
	}
	cert, err := utils.ParseCertificate([]byte(dbCert.CertificatePem))
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	keyPair, err := query.GetKeyByID(ctx, rc.KeyID)
	if err != nil {
		return fmt.Errorf("failed to fetch Key from DB: %w", err)
	}

	privateKey, publicKey, err := utils.ParseKeys([]byte(keyPair.PrivateKeyPem), []byte(keyPair.PublicKeyPem))
	if err != nil {
		return fmt.Errorf("failed to parse keys: %w", err)
	}

	certType := domain.CertType(dbCert.Type)

	var issuerCert *x509.Certificate
	var issuerPrivateKey any
	var issuerSerial string

	if certType == domain.TypeRootCA {
		issuerCert = nil
		issuerPrivateKey = nil
		issuerSerial = ""
	} else {
		if rc.IssuerID == 0 {
			return fmt.Errorf("issuer ID (--iss) is required when rotating Intermediate or Leaf certificates")
		}

		issuerDBCert, err := query.GetCertificateByID(ctx, rc.IssuerID)
		if err != nil {
			return fmt.Errorf("failed to fetch Issuer Certificate from DB: %w", err)
		}

		issuerCert, err = utils.ParseCertificate([]byte(issuerDBCert.CertificatePem))
		if err != nil {
			return fmt.Errorf("failed to parse Issuer Certificate: %w", err)
		}

		if !issuerCert.IsCA {
			return fmt.Errorf("specified issuer (ID: %d) is not a valid CA (IsCA=false)", rc.IssuerID)
		}

		if time.Now().After(issuerCert.NotAfter) {
			return fmt.Errorf("failed to rotate certificate: specified issuer (ID: %d) has expired", rc.IssuerID)
		}

		issuerKeys, err := query.GetKeyByID(ctx, issuerDBCert.KeyID)
		if err != nil {
			return fmt.Errorf("failed to fetch Issuer key from DB: %w", err)
		}

		issuerPrivateKey, _, err = utils.ParseKeys([]byte(issuerKeys.PrivateKeyPem), []byte(issuerKeys.PublicKeyPem))
		if err != nil {
			return fmt.Errorf("failed to parse Issuer private key: %w", err)
		}

		issuerSerial = fmt.Sprintf("%x", issuerCert.SerialNumber)
	}

	var pathLen *int
	if certType == domain.TypeIntermediate {
		if cert.MaxPathLenZero {
			zero := 0
			pathLen = &zero
		} else if cert.MaxPathLen > 0 {
			pl := cert.MaxPathLen
			pathLen = &pl
		}
	}

	ttlHours := int(cert.NotAfter.Sub(cert.NotBefore).Hours())

	newCert, err := domain.IssueCertificate(domain.CertOptions{
		Type:    certType,
		Subject: cert.Subject,
		SANs: domain.SANs{
			DNSNames:       cert.DNSNames,
			EmailAddresses: cert.EmailAddresses,
			IPAddresses:    cert.IPAddresses,
			URIs:           cert.URIs,
		},
		TTLInHours: ttlHours,
		KeyPair: &domain.KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		},
		ParentCert: issuerCert,
		ParentKey:  issuerPrivateKey,
		Usages: &domain.KeyUsageConfig{
			KeyUsages:    utils.ParseKeyUsages(utils.MarshalKeyUsage(cert.KeyUsage)),
			ExtKeyUsages: utils.ParseExtKeyUsages(utils.MarshalExtKeyUsages(cert.ExtKeyUsage)),
		},
		PathLen: pathLen,
	})
	if err != nil {
		return fmt.Errorf("failed to issue rotated Certificate: %w", err)
	}

	newCertPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: newCert.Raw,
	})

	skidHex := hex.EncodeToString(newCert.SubjectKeyId)
	akidHex := hex.EncodeToString(newCert.AuthorityKeyId)

	err = _db_.RunInTx(ctx, db, func(txQuerier base.Querier) error {
		_, err = txQuerier.CreateCertificate(ctx, base.CreateCertificateParams{
			SerialNumber:       fmt.Sprintf("%x", newCert.SerialNumber),
			CommonName:         newCert.Subject.CommonName,
			Type:               dbCert.Type,
			KeyID:              rc.KeyID,
			IssuerSerialNumber: sql.NullString{String: issuerSerial, Valid: issuerSerial != ""},
			Skid:               skidHex,
			Akid:               akidHex,
			Status:             "ACTIVE",
			NotBefore:          newCert.NotBefore,
			NotAfter:           newCert.NotAfter,
			CertificatePem:     string(newCertPem),
		})
		if err != nil {
			return fmt.Errorf("failed to insert new rotated Certificate in DB: %w", err)
		}

		_, err = txQuerier.UpdateCertificate(ctx, base.UpdateCertificateParams{
			Status:       sql.NullString{String: "REVOKED", Valid: true},
			SerialNumber: dbCert.SerialNumber,
		})
		if err != nil {
			return fmt.Errorf("failed to update old Certificate status in DB: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("transaction failed, data rolled back: %w", err)
	}

	log.Printf("Success: Successfully rotated certificate (Old Serial: %s, Type: %s)", dbCert.SerialNumber, dbCert.Type)
	return nil
}
