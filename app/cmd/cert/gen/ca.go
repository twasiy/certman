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
package gen

import (
	"context"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"pkit/app/domain"
	"pkit/app/utils"
	"pkit/db/base"
)

type CACmd struct {
	CommonName         string   `name:"cn" required:"" help:"Common Name (CN) of the certificate subject."`
	Country            []string `name:"c" help:"Country (C) code(s) for the certificate subject."`
	Organization       []string `name:"o" help:"Organization (O) name(s) for the certificate subject."`
	OrganizationalUnit []string `name:"ou" help:"Organizational Unit (OU) name(s) for the certificate subject."`
	Locality           []string `name:"locality" help:"Locality or city (L) name(s) for the certificate subject."`
	Province           []string `name:"st" help:"State or province (ST) name(s) for the certificate subject."`
	StreetAddress      []string `name:"street" help:"Street address(es) for the certificate subject."`
	PostalCode         []string `name:"postal-code" help:"Postal code(s) for the certificate subject."`
	TTL                string   `name:"ttl" required:"" default:"86400h" help:"Validity duration/time-to-live for the certificate (e.g., 8760h, 30d, 10y)."`
	KeyUsages          []string `name:"ku" enum:"digital-signature,content-commitment,key-encipherment,data-encipherment,key-agreement,cert-sign,crl-sign,encipher-only,decipher-only" help:"Key usage extensions to enable (can be specified multiple times or comma-separated)."`

	KeyID int64 `name:"kid" help:"Database ID of the cryptographic key pair used to sign the certificate."`
}

func (cc *CACmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	hours, err := utils.ParseTTLToHours(cc.TTL)
	if err != nil {
		return fmt.Errorf("invalid TTL value: %w", err)
	}

	dbKey, err := query.GetKeyByID(ctx, cc.KeyID)
	if err != nil {
		return fmt.Errorf("failed to get Key from DB: %w", err)
	}

	privateKey, publicKey, err := utils.ParseKeys([]byte(dbKey.PrivateKeyPem), []byte(dbKey.PublicKeyPem))
	if err != nil {
		return err
	}

	caCert, err := domain.IssueCertificate(domain.CertOptions{
		Type: domain.TypeRootCA,
		Subject: pkix.Name{
			Country:            cc.Country,
			Organization:       cc.Organization,
			OrganizationalUnit: cc.OrganizationalUnit,
			Locality:           cc.Locality,
			Province:           cc.Province,
			StreetAddress:      cc.StreetAddress,
			PostalCode:         cc.PostalCode,
			CommonName:         cc.CommonName,
		},
		TTLInHours: hours,
		KeyPair: &domain.KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		},
		ParentCert: nil,
		ParentKey:  nil,
		Usages: &domain.KeyUsageConfig{
			KeyUsages: utils.ParseKeyUsages(cc.KeyUsages),
		},
		PathLen: nil,
	})
	if err != nil {
		return fmt.Errorf("failed to generate CA Certificate: %w", err)
	}

	// ------------------------- WRITING TO THE DB ------------------------------

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})

	var skidHex, akidHex string
	if len(caCert.SubjectKeyId) > 0 {
		skidHex = hex.EncodeToString(caCert.SubjectKeyId)
	}
	if len(caCert.AuthorityKeyId) > 0 {
		akidHex = hex.EncodeToString(caCert.AuthorityKeyId)
	} else {
		// Fallback for self-signed root anchors
		akidHex = skidHex
	}

	_, err = query.CreateCertificate(ctx, base.CreateCertificateParams{
		SerialNumber:       fmt.Sprintf("%x", caCert.SerialNumber),
		CommonName:         caCert.Subject.CommonName,
		KeyID:              dbKey.ID,
		IssuerSerialNumber: sql.NullString{String: "", Valid: false},
		Skid:               skidHex,
		Akid:               akidHex,
		Status:             "ACTIVE",
		NotBefore:          caCert.NotBefore,
		NotAfter:           caCert.NotAfter,
		CertificatePem:     string(certPem),
	})
	if err != nil {
		return fmt.Errorf("failed to create Certificate in DB: %w", err)
	}

	log.Println("Success: successfully Created Certificate.")

	return nil
}
