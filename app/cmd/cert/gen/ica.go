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

type ICACmd struct {
	CommonName         string   `name:"cn" required:"" help:"Common Name (CN) of the certificate subject."`
	Country            []string `name:"c" help:"Country (C) code(s) for the certificate subject."`
	Organization       []string `name:"o" help:"Organization (O) name(s) for the certificate subject."`
	OrganizationalUnit []string `name:"ou" help:"Organizational Unit (OU) name(s) for the certificate subject."`
	Locality           []string `name:"locality" help:"Locality or city (L) name(s) for the certificate subject."`
	Province           []string `name:"st" help:"State or province (ST) name(s) for the certificate subject."`
	StreetAddress      []string `name:"street" help:"Street address(es) for the certificate subject."`
	PostalCode         []string `name:"postal-code" help:"Postal code(s) for the certificate subject."`
	KeyType            string   `name:"type" required:"" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ecdsa-256" help:"Cryptographic algorithm and key size to generate for the certificate."`
	TTL                string   `name:"ttl" required:"" default:"17280h" help:"Validity duration/time-to-live for the certificate (e.g., 8760h, 30d, 10y)."`
	DNSNames           []string `name:"dns" help:"DNS Subject Alternative Names (SANs)."`
	EmailAddresses     []string `name:"email" help:"Email Subject Alternative Names (SANs)."`
	IPAddresses        []string `name:"ip" help:"IP address Subject Alternative Names (SANs)."`
	URIs               []string `name:"uri" help:"URI Subject Alternative Names (SANs)."`
	KeyUsages          []string `name:"ku" enum:"digital-signature,content-commitment,key-encipherment,data-encipherment,key-agreement,cert-sign,crl-sign,encipher-only,decipher-only" help:"Key usage extensions to enable (can be specified multiple times or comma-separated)."`
	ExtKeyUsages       []string `name:"eku" enum:"any,server-auth,client-auth,code-signing,email-protection,time-stamping,ocsp-signing" help:"Extended key usage (EKU) extensions to enable (can be specified multiple times or comma-separated)."`
	PathLen            int      `name:"path-len" help:"Maximum allowed path length for downstream CA certificates in the chain."`

	IssuerID int64 `name:"iss" help:"Database ID of the issuing parent certificate."`
	KeyID    int64 `name:"kid" help:"Database ID of the cryptographic key pair used to sign the certificate."`
}

func (ic *ICACmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	hours, err := utils.ParseTTLToHours(ic.TTL)
	if err != nil {
		return fmt.Errorf("invalid TTL value: %w", err)
	}

	dbKey, err := query.GetKeyByID(ctx, ic.KeyID)
	if err != nil {
		return fmt.Errorf("failed to fetch certificate from DB: %w", err)
	}

	privateKey, publicKey, err := utils.ParseKeys([]byte(dbKey.PrivateKeyPem), []byte(dbKey.PublicKeyPem))
	if err != nil {
		return err
	}

	issuerDBCert, err := query.GetCertificateByID(ctx, ic.IssuerID)
	if err != nil {
		return fmt.Errorf("failed to fetch issuer Certificate from DB: %w", err)
	}
	issuerCert, err := utils.ParseCertificate([]byte(issuerDBCert.CertificatePem))
	if err != nil {
		return err
	}

	issuerKeys, err := query.GetKeyByID(ctx, issuerDBCert.KeyID)
	if err != nil {
		return fmt.Errorf("failed to fetch key from DB: %w", err)
	}

	issuerPrivateKey, _, err := utils.ParseKeys([]byte(issuerKeys.PrivateKeyPem), []byte(issuerKeys.PublicKeyPem))
	if err != nil {
		return err
	}

	icaCert, err := domain.IssueCertificate(domain.CertOptions{
		Type: domain.TypeIntermediate,
		Subject: pkix.Name{
			Country:            ic.Country,
			Organization:       ic.Organization,
			OrganizationalUnit: ic.OrganizationalUnit,
			Locality:           ic.Locality,
			Province:           ic.Province,
			StreetAddress:      ic.StreetAddress,
			PostalCode:         ic.PostalCode,
			CommonName:         ic.CommonName,
		},
		SANs: domain.SANs{
			DNSNames:       ic.DNSNames,
			EmailAddresses: ic.EmailAddresses,
			IPAddresses:    utils.ToNetIPs(ic.IPAddresses),
			URIs:           utils.ToURLs(ic.URIs),
		},
		TTLInHours: hours,
		KeyPair: &domain.KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		},
		ParentCert: issuerCert,
		ParentKey:  issuerPrivateKey,
		Usages: &domain.KeyUsageConfig{
			KeyUsages:    utils.ParseKeyUsages(ic.KeyUsages),
			ExtKeyUsages: utils.ParseExtKeyUsages(ic.ExtKeyUsages),
		},
		PathLen: new(ic.PathLen),
	})
	if err != nil {
		return fmt.Errorf("cannot generate Intermediate CA Certificate: %w", err)
	}

	// -------------------------------- WRITING TO THE DB --------------------------------------

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: icaCert.Raw,
	})

	skidHex := hex.EncodeToString(icaCert.SubjectKeyId)
	akidHex := hex.EncodeToString(icaCert.AuthorityKeyId)

	_, err = query.CreateCertificate(ctx, base.CreateCertificateParams{
		SerialNumber:       fmt.Sprintf("%x", icaCert.SerialNumber),
		CommonName:         icaCert.Subject.CommonName,
		Type:               "INTERMEDIATE-CA",
		KeyID:              dbKey.ID,
		IssuerSerialNumber: sql.NullString{String: fmt.Sprintf("%x", issuerDBCert.SerialNumber), Valid: true},
		Skid:               skidHex,
		Akid:               akidHex,
		Status:             "ACTIVE",
		NotBefore:          icaCert.NotBefore,
		NotAfter:           icaCert.NotAfter,
		CertificatePem:     string(certPem),
	})
	if err != nil {
		return fmt.Errorf("failed to create Certificate in DB: %w", err)
	}

	log.Println("Success: successfully Created Certificate.")

	return nil
}
