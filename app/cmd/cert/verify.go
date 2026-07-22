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
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"pkit/app/utils"
	"pkit/db/base"
	"time"
)

type VerifyCmd struct {
	ID int64 `arg:"" help:"Database ID of the certificate to verify."`
}

func (vc *VerifyCmd) Run(ctx context.Context, query base.Querier) error {
	dbCert, err := query.GetCertificateByID(ctx, vc.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch certificate from DB: %w", err)
	}

	cert, err := utils.ParseCertificate([]byte(dbCert.CertificatePem))
	if err != nil {
		return fmt.Errorf("failed to parse target certificate: %w", err)
	}

	// Build and walk the trust chain upward using AKID -> SKID pointers
	chain := []*x509.Certificate{cert}
	workingCert := cert

	fmt.Println("Building and verifying trust chain...")

	const maxChainDepth = 10
	for depth := range maxChainDepth {
		if workingCert.Subject.String() == workingCert.Issuer.String() {
			fmt.Printf(" Root Anchor Found: %s\n", workingCert.Subject.CommonName)
			break
		}

		if len(workingCert.AuthorityKeyId) == 0 {
			return fmt.Errorf("Verification Failed: Chain broken. Certificate '%s' is not self-signed but lacks an Authority Key Identifier extension", workingCert.Subject.CommonName)
		}

		akidHex := hex.EncodeToString(workingCert.AuthorityKeyId)

		parentDBCert, err := query.GetCertificateBySKID(ctx, akidHex)
		if err != nil {
			return fmt.Errorf("Verification Failed: Trust chain broken. Authority Certificate with SKID [%s] (Issuer: %s) could not be found in the system: %w", akidHex, workingCert.Issuer.CommonName, err)
		}

		parentCert, err := utils.ParseCertificate([]byte(parentDBCert.CertificatePem))
		if err != nil {
			return fmt.Errorf("failed to parse parent certificate: %w", err)
		}

		if err := workingCert.CheckSignatureFrom(parentCert); err != nil {
			return fmt.Errorf("Verification Failed: Cryptographic signature mismatch between %s and issuer %s: %w", workingCert.Subject.CommonName, parentCert.Subject.CommonName, err)
		}

		fmt.Printf(" Verified signature by: %s\n", parentCert.Subject.CommonName)

		chain = append(chain, parentCert)
		workingCert = parentCert

		if depth == maxChainDepth-1 {
			return fmt.Errorf("Verification Failed: Exceeded maximum allowed chain depth (%d)", maxChainDepth)
		}
	}
	now := time.Now()
	for _, cert := range chain {
		if now.Before(cert.NotBefore) {
			return fmt.Errorf("Verification Failed: Certificate '%s' is not active yet (Valid from: %s)", cert.Subject.CommonName, cert.NotBefore.Format("2006-01-02 15:04:05 UTC"))
		}
		if now.After(cert.NotAfter) {
			return fmt.Errorf("Verification Failed: Certificate '%s' expired on %s", cert.Subject.CommonName, cert.NotAfter.Format("2006-01-02 15:04:05 UTC"))
		}
	}

	rootCert := chain[len(chain)-1]
	if err := rootCert.CheckSignatureFrom(rootCert); err != nil {
		return fmt.Errorf("Verification Failed: Root certificate is self-signed but possesses a corrupt or invalid self-signature: %w", err)
	}

	fmt.Println("\nCertificate chain successfully verified against a trusted local root anchor!")
	return nil
}
