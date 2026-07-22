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
	"os"
	"text/tabwriter"
)

type VerifyCmd struct {
	ID int64 `arg:"" help:"Database ID of the CSR to verify."`
}

func (vc *VerifyCmd) Run(ctx context.Context, query base.Querier) error {
	csrRecord, err := query.GetCSRByID(ctx, vc.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch CSR from DB: %w", err)
	}

	block, _ := pem.Decode([]byte(csrRecord.CsrPem))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return fmt.Errorf("invalid PEM block in database")
	}

	parsedCSR, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse X.509 CSR: %w", err)
	}

	// Track verification checks
	var issues []string

	// Cryptographic Signature
	if err := parsedCSR.CheckSignature(); err != nil {
		issues = append(issues, fmt.Sprintf("Signature: INVALID (%v)", err))
	}

	// Key Strength & Algorithm
	keyDetail := "Unknown"
	switch pub := parsedCSR.PublicKey.(type) {
	case *rsa.PublicKey:
		bitLen := pub.N.BitLen()
		keyDetail = fmt.Sprintf("RSA %d-bit", bitLen)
		if bitLen < 2048 {
			issues = append(issues, fmt.Sprintf("Key Strength: WEAK (%d bits < 2048 required)", bitLen))
		}
	default:
		keyDetail = fmt.Sprintf("%T", pub)
	}

	if csrRecord.KeyID != 0 {
		keyRecord, err := query.GetKeyByID(ctx, csrRecord.KeyID)
		if err == nil {
			keyBlock, _ := pem.Decode([]byte(keyRecord.PublicKeyPem))
			if keyBlock != nil {
				storedPubKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
				if err == nil {
					if !pubKeysEqual(parsedCSR.PublicKey, storedPubKey) {
						issues = append(issues, "Key Match: Public key does NOT match stored key pair")
					}
				}
			}
		}
	}

	// Common Name Presence
	if parsedCSR.Subject.CommonName == "" {
		issues = append(issues, "Subject: Missing Common Name (CN)")
	}

	// --- PRINT DIAGNOSTIC REPORT ---
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "PROPERTY\tVALUE\n")
	fmt.Fprintf(w, "--------\t-----\n")
	fmt.Fprintf(w, "CSR ID\t%d\n", csrRecord.ID)
	fmt.Fprintf(w, "Common Name\t%s\n", parsedCSR.Subject.CommonName)
	fmt.Fprintf(w, "DNS Names (SANs)\t%v\n", parsedCSR.DNSNames)
	fmt.Fprintf(w, "IP Addresses\t%v\n", parsedCSR.IPAddresses)
	fmt.Fprintf(w, "Key Type\t%s\n", keyDetail)
	fmt.Fprintf(w, "Status\t%s\n", csrRecord.Status)
	w.Flush()

	fmt.Println()
	if len(issues) > 0 {
		fmt.Println(" Verification Failed with the following issues:")
		for _, issue := range issues {
			fmt.Printf("  - %s\n", issue)
		}
		return fmt.Errorf("CSR verification failed")
	}

	fmt.Println(" CSR passed all integrity and policy checks!")
	return nil
}

// Helper to compare two public keys
func pubKeysEqual(a, b any) bool {
	rsaA, okA := a.(*rsa.PublicKey)
	rsaB, okB := b.(*rsa.PublicKey)
	if okA && okB {
		return rsaA.N.Cmp(rsaB.N) == 0 && rsaA.E == rsaB.E
	}
	return false
}
