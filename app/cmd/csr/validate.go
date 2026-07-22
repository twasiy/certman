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
	"certman/db/base"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type ValidateCmd struct {
	ID int64 `arg:"" help:"Database ID of the CSR to validate."`
}

func (vc *ValidateCmd) Run(ctx context.Context, query base.Querier) error {
	dbCsr, err := query.GetCSRByID(ctx, vc.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch CSR from DB: %w", err)
	}

	block, _ := pem.Decode([]byte(dbCsr.CsrPem))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return fmt.Errorf("invalid PEM block in DB for CSR #%d", vc.ID)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse X.509 CSR: %w", err)
	}

	fmt.Printf("Validating CSR ID %d [%s]...\n\n", vc.ID, csr.Subject.CommonName)

	var issues []string
	var warnings []string

	// Common Name Presence
	if csr.Subject.CommonName == "" {
		issues = append(issues, "Subject missing Common Name (CN)")
	}

	// Cryptographic Signature Algorithm Checks
	switch csr.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		issues = append(issues, fmt.Sprintf("Insecure signature algorithm used in CSR: %s", csr.SignatureAlgorithm))
	}

	// Public Key Bit Strength
	if rsaKey, ok := csr.PublicKey.(*rsa.PublicKey); ok {
		keySize := rsaKey.N.BitLen()
		if keySize < 2048 {
			issues = append(issues, fmt.Sprintf("Weak RSA key length (%d bits; minimum required is 2048 bits)", keySize))
		}
	}

	// SAN Recommendation Warning
	if len(csr.DNSNames) == 0 && len(csr.IPAddresses) == 0 {
		warnings = append(warnings, "CSR contains no Subject Alternative Names (DNS/IP SANs)")
	}

	// Output Warnings
	if len(warnings) > 0 {
		fmt.Println(" Warnings:")
		for _, w := range warnings {
			fmt.Printf("  - %s\n", w)
		}
	}

	// Output Issues & Exit Status
	if len(issues) > 0 {
		fmt.Println("\n Validation Failed:")
		for _, issue := range issues {
			fmt.Printf("  - %s\n", issue)
		}
		return fmt.Errorf("csr validation failed with %d error(s)", len(issues))
	}

	fmt.Println(" All CSR sanity checks passed!")
	return nil
}
