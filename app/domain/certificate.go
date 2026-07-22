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
package domain

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"pkit/app/utils"
)

// CertType defines the role of the certificate in the PKI hierarchy.
type CertType string

const (
	TypeRootCA       CertType = "CA"
	TypeIntermediate CertType = "INTERMEDIATE"
	TypeLeaf         CertType = "LEAF"
)

// CertOptions holds parameters for generating Root CAs, Intermediates, or Leaf certificates.
type CertOptions struct {
	Type       CertType
	Subject    pkix.Name
	SANs       SANs
	TTLInHours int
	KeyPair    *KeyPair          // Target cert key pair
	ParentCert *x509.Certificate // Issuer cert (nil if self-signed Root CA)
	ParentKey  any               // Issuer private key (nil if self-signed Root CA)
	Usages     *KeyUsageConfig   // Custom key usages (optional)

	// PathLen controls intermediate CA path constraints.
	// - Use a pointer (*int) so nil means "no constraint specified".
	// - Pass a pointer to 0 for MaxPathLen = 0 (leaf signing only).
	// - Pass a pointer to >0 for nested intermediate depth limits.
	PathLen *int
}

// IssueCertificate is the unified builder for generating any X.509 certificate tier.
func IssueCertificate(opts CertOptions) (*x509.Certificate, error) {
	if opts.KeyPair == nil || opts.KeyPair.PublicKey == nil {
		return nil, errors.New("target keypair with public key is required")
	}

	serialNumber, err := utils.GetSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// 1. Base Template Setup
	isCA := opts.Type == TypeRootCA || opts.Type == TypeIntermediate
	template := GetBaseTemplate(opts.Subject, serialNumber, opts.TTLInHours, isCA)

	// 2. Set SANs (for Intermediate and Leaf)
	if opts.Type != TypeRootCA {
		template.DNSNames = opts.SANs.DNSNames
		template.EmailAddresses = opts.SANs.EmailAddresses
		template.IPAddresses = opts.SANs.IPAddresses
		template.URIs = opts.SANs.URIs
	}

	// 3. Handle Path Length Constraints for Intermediates
	if opts.Type == TypeIntermediate && opts.PathLen != nil {
		if *opts.PathLen == 0 {
			template.MaxPathLen = 0
			template.MaxPathLenZero = true // Strictly restricts this CA to only sign leaf certs
		} else if *opts.PathLen > 0 {
			template.MaxPathLen = *opts.PathLen
			template.MaxPathLenZero = false
		}
	}

	// 4. Configure Key Usages
	applyKeyUsages(template, opts)

	// 5. Configure Key Identifiers (SKID & AKID)
	skid, err := GenerateSKID(opts.KeyPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SKID: %w", err)
	}
	template.SubjectKeyId = skid

	// 6. Issuer & Signing Setup
	var signingCert *x509.Certificate
	var signingKey any

	if opts.Type == TypeRootCA {
		// Self-signed Root CA
		template.AuthorityKeyId = skid
		signingCert = template
		signingKey = opts.KeyPair.PrivateKey
	} else {
		// Signed by Parent CA (Root or another Intermediate)
		if opts.ParentCert == nil || opts.ParentKey == nil {
			return nil, fmt.Errorf("parent certificate and private key required for type: %s", opts.Type)
		}
		if !opts.ParentCert.IsCA {
			return nil, errors.New("parent certificate must be a CA")
		}
		template.AuthorityKeyId = opts.ParentCert.SubjectKeyId
		signingCert = opts.ParentCert
		signingKey = opts.ParentKey
	}

	// 7. Create & Parse Final Certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, signingCert, opts.KeyPair.PublicKey, signingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	return cert, nil
}

// GetBaseTemplate generates the basic certificate scaffolding.
func GetBaseTemplate(subject pkix.Name, serialNumber *big.Int, ttlInHour int, isCA bool) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(ttlInHour) * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true, // Crucial for CA validation
	}
}

// Internal helper to apply key usages dynamically or fall back to standard defaults.
func applyKeyUsages(template *x509.Certificate, opts CertOptions) {
	if opts.Usages != nil && len(opts.Usages.KeyUsages) > 0 {
		template.KeyUsage = 0
		for _, ku := range opts.Usages.KeyUsages {
			template.KeyUsage |= ku
		}
	} else {
		// Default Usages
		if template.IsCA {
			template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		} else {
			template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		}
	}

	if opts.Usages != nil && len(opts.Usages.ExtKeyUsages) > 0 {
		template.ExtKeyUsage = opts.Usages.ExtKeyUsages
	} else if opts.Type == TypeLeaf {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
}
