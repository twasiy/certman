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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"fmt"
	"log"
	"pkit/app/utils"
	"pkit/db/base"
)

type GenerateCmd struct {
	CommonName         string   `name:"cn" required:"" help:"Common Name (CN) of the CSR subject."`
	Country            []string `name:"c" help:"Country (C) code(s) for the CSR subject."`
	Organization       []string `name:"o" help:"Organization (O) name(s) for the CSR subject."`
	OrganizationalUnit []string `name:"ou" help:"Organizational Unit (OU) name(s) for the CSR subject."`
	Locality           []string `name:"locality" help:"Locality or city (L) name(s) for the CSR subject."`
	Province           []string `name:"st" help:"State or province (ST) name(s) for the CSR subject."`
	StreetAddress      []string `name:"street" help:"Street address(es) for the CSR subject."`
	PostalCode         []string `name:"postal-code" help:"Postal code(s) for the CSR subject."`
	KeyType            string   `name:"type" required:"" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ecdsa-256" help:"Cryptographic algorithm and key size to generate for the CSR."`
	DNSNames           []string `name:"dns" help:"DNS Subject Alternative Names (SANs)."`
	EmailAddresses     []string `name:"email" help:"Email Subject Alternative Names (SANs)."`
	IPAddresses        []string `name:"ip" help:"IP address Subject Alternative Names (SANs)."`
	URIs               []string `name:"uri" help:"URI Subject Alternative Names (SANs)."`

	KeyID int64 `name:"kid" help:"Database ID of the cryptographic key pair to associate with the CSR."`
}

func (gc *GenerateCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	dbKey, err := query.GetKeyByID(ctx, gc.KeyID)
	if err != nil {
		return fmt.Errorf("failed to fetch Key from DB: %w", err)
	}

	privateKey, _, err := utils.ParseKeys([]byte(dbKey.PrivateKeyPem), []byte(dbKey.PublicKeyPem))
	if err != nil {
		return err
	}

	signatureAlgo, err := utils.GetSignatureAlgorithm(gc.KeyType)
	if err != nil {
		return err
	}

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            gc.Country,
			Organization:       gc.Organization,
			OrganizationalUnit: gc.OrganizationalUnit,
			Locality:           gc.Locality,
			Province:           gc.Province,
			StreetAddress:      gc.StreetAddress,
			PostalCode:         gc.PostalCode,
			CommonName:         gc.CommonName,
		},
		DNSNames:       gc.DNSNames,
		EmailAddresses: gc.EmailAddresses,
		IPAddresses:    utils.ToNetIPs(gc.IPAddresses),
		URIs:           utils.ToURLs(gc.URIs),

		SignatureAlgorithm: signatureAlgo,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	csrPem, err := utils.EncodeToPem(csr, "CERTIFICATE REQUEST")
	if err != nil {
		return err
	}

	// ------------------------------ WRITING TO THE DATABASE ------------------------------

	_, err = query.CreateCSR(ctx, base.CreateCSRParams{
		CommonName:    csrTemplate.Subject.CommonName,
		KeyID:         dbKey.ID,
		Status:        "PENDING",
		CsrPem:        string(csrPem),
		CertificateID: sql.NullInt64{Int64: 0, Valid: false},
	})
	if err != nil {
		return fmt.Errorf("failed to create CSR in DB: %w", err)
	}

	log.Println("Success: successfully Created Certificate Signing Request.")

	return nil
}
