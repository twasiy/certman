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
package crl

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"fmt"
	"time"
)

type VerifyCmd struct {
	ID int64 `arg:"" help:"Database ID of the CRL to verify."`
}

func (vc *VerifyCmd) Run(ctx context.Context, query base.Querier) error {
	crlRecord, err := query.GetCRLByID(ctx, vc.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch CRL from DB: %w", err)
	}

	issuerDBCert, err := query.GetCertificateByID(ctx, crlRecord.IssuerID)
	if err != nil {
		return fmt.Errorf("failed to get issuer certificate (%d) for verification: %w", crlRecord.ID, err)
	}

	parsedCRL, err := utils.ParseCRL([]byte(crlRecord.CrlPem))
	if err != nil {
		return err
	}

	issuerCert, err := utils.ParseCertificate([]byte(issuerDBCert.CertificatePem))
	if err != nil {
		return err
	}

	err = parsedCRL.CheckSignatureFrom(issuerCert)
	if err != nil {
		return fmt.Errorf(" CRL cryptographic verification failed: signature mismatch: %w", err)
	}

	fmt.Println(" Cryptographic Signature: Valid (Signed securely by the Issuer)")

	now := time.Now()
	if now.After(parsedCRL.NextUpdate) {
		fmt.Printf("  Validity Warning: This CRL is EXPIRED!\n")
		fmt.Printf("   Next Update was scheduled for: %s\n", parsedCRL.NextUpdate.Format("2006-01-02 15:04:05"))
	} else {
		fmt.Printf("Validity Status: Current (Expires on: %s)\n", parsedCRL.NextUpdate.Format("2006-01-02 15:04:05"))
	}

	return nil
}
