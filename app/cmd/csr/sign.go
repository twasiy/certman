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
package csr

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"pkit/app/domain"
	"pkit/app/utils"
	_db_ "pkit/db"
	"pkit/db/base"
)

type SignCmd struct {
	ID           int64    `arg:"" help:"Database ID of the CSR to sign."`
	Type         string   `name:"type" required:"" help:"Type of certificate to issue (e.g., CA, INTERMEDIATE, LEAF)."`
	TTL          string   `name:"ttl" required:"" default:"8760h" help:"Validity duration/time-to-live for the issued certificate (e.g., 8760h, 30d, 1y)."`
	KeyUsages    []string `name:"ku" enum:"digital-signature,content-commitment,key-encipherment,data-encipherment,key-agreement,cert-sign,crl-sign,encipher-only,decipher-only" help:"Key usage extensions to enable (can be specified multiple times or comma-separated)."`
	ExtKeyUsages []string `name:"eku" enum:"any,server-auth,client-auth,code-signing,email-protection,time-stamping,ocsp-signing" help:"Extended key usage (EKU) extensions to enable (can be specified multiple times or comma-separated)."`
	PathLen      int      `name:"path-len" help:"Maximum allowed path length for downstream CA certificates (omit for non-CA certificates)."`

	IssuerID int64 `name:"iss" help:"Database ID of the issuing parent certificate."`
}

func (sc *SignCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	hours, err := utils.ParseTTLToHours(sc.TTL)
	if err != nil {
		return fmt.Errorf("invalid TTL value: %w", err)
	}

	dbCsr, err := query.GetCSRByID(ctx, sc.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch CSR from DB: %w", err)
	}

	csrBlock, _ := pem.Decode([]byte(dbCsr.CsrPem))
	if csrBlock == nil {
		return errors.New("failed to decode CSR pem block")
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CSR: %w", err)
	}

	issuerDBCert, err := query.GetCertificateByID(ctx, int64(sc.IssuerID))
	if err != nil {
		return fmt.Errorf("failed to fetch Certificate from DB: %w", err)
	}
	issuerDBKeys, err := query.GetKeyByID(ctx, issuerDBCert.KeyID)
	if err != nil {
		return fmt.Errorf("failed to fetch issuer keys from DB: %w", err)
	}

	issuerCert, err := utils.ParseCertificate([]byte(issuerDBCert.CertificatePem))
	if err != nil {
		return err
	}
	issuerPrivKey, _, err := utils.ParseKeys([]byte(issuerDBKeys.PrivateKeyPem), []byte(issuerDBKeys.PublicKeyPem))
	if err != nil {
		return err
	}

	cert, err := domain.IssueCertificate(domain.CertOptions{
		Type:    domain.CertType(sc.Type),
		Subject: csr.Subject,
		SANs: domain.SANs{
			DNSNames:       csr.DNSNames,
			IPAddresses:    csr.IPAddresses,
			EmailAddresses: csr.EmailAddresses,
			URIs:           csr.URIs,
		},
		TTLInHours: hours,
		KeyPair: &domain.KeyPair{
			PublicKey: csr.PublicKey,
		},
		ParentCert: issuerCert,
		ParentKey:  issuerPrivKey,
		Usages: &domain.KeyUsageConfig{
			KeyUsages:    utils.ParseKeyUsages(sc.KeyUsages),
			ExtKeyUsages: utils.ParseExtKeyUsages(sc.ExtKeyUsages),
		},
		PathLen: &sc.PathLen,
	})
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// ------------------------------ WRITING TO THE DATABASE ------------------------------

	certPemBytes, err := utils.EncodeToPem(cert.Raw, "CERTIFICATE")
	if err != nil {
		return err
	}

	err = _db_.RunInTx(ctx, db, func(txQuerier base.Querier) error {
		newCert, err := txQuerier.CreateCertificate(ctx, base.CreateCertificateParams{
			SerialNumber:       cert.SerialNumber.String(),
			CommonName:         cert.Subject.CommonName,
			Type:               sc.Type,
			KeyID:              dbCsr.KeyID,
			IssuerSerialNumber: sql.NullString{String: issuerCert.SerialNumber.String(), Valid: true},
			Skid:               hex.EncodeToString(cert.SubjectKeyId),
			Akid:               hex.EncodeToString(cert.AuthorityKeyId),
			NotBefore:          cert.NotBefore,
			NotAfter:           cert.NotAfter,
			CertificatePem:     certPemBytes,
		})
		if err != nil {
			return fmt.Errorf("failed to create Certificate in DB: %w", err)
		}

		err = txQuerier.UpdateCSRStatus(ctx, base.UpdateCSRStatusParams{
			Status:        "SIGNED",
			CertificateID: sql.NullInt64{Int64: newCert.ID, Valid: true},
			CommonName:    dbCsr.CommonName,
		})
		if err != nil {
			return fmt.Errorf("failed to update csr status: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("transaction failed, data rolled back: %w", err)
	}

	log.Println("Succes: successfully created Certificate.")

	return nil
}
