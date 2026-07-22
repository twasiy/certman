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
	"crypto/x509"
	"fmt"
	"time"
)

type ValidateCmd struct {
	ID int64 `arg:"" help:"Database ID of the CRL to validate."`
}

func (vc *ValidateCmd) Run(ctx context.Context, query base.Querier) error {
	dbCRL, err := query.GetCRLByID(ctx, vc.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch CRL from DB: %w", err)
	}

	crl, err := utils.ParseCRL([]byte(dbCRL.CrlPem))
	if err != nil {
		return fmt.Errorf("failed to parse CRL: %w", err)
	}

	fmt.Printf("Validating CRL ID %d [%s]...\n\n", vc.ID, dbCRL.Name)

	var issues []string
	var warnings []string

	now := time.Now()

	// Check ThisUpdate (Cannot be in the future)
	if now.Before(crl.ThisUpdate) {
		issues = append(issues, fmt.Sprintf("CRL 'ThisUpdate' is in the future (Valid starting: %s)", crl.ThisUpdate.Format("2006-01-02 15:04:05 UTC")))
	}

	// Check NextUpdate (Expirations and upcoming expiration warnings)
	if !crl.NextUpdate.IsZero() {
		if now.After(crl.NextUpdate) {
			issues = append(issues, fmt.Sprintf("CRL expired on %s", crl.NextUpdate.Format("2006-01-02 15:04:05 UTC")))
		} else {
			hoursRemaining := time.Until(crl.NextUpdate).Hours()
			if hoursRemaining <= 24 {
				warnings = append(warnings, fmt.Sprintf("CRL expires soon (%.1f hours remaining)", hoursRemaining))
			}
		}
	} else {
		warnings = append(warnings, "CRL lacks a 'NextUpdate' field; expiration bounds cannot be enforced automatically")
	}

	// Cryptographic Signature Algorithm Sanity
	switch crl.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		issues = append(issues, fmt.Sprintf("Insecure signature algorithm used for CRL: %s", crl.SignatureAlgorithm))
	}

	// Verify CRL Sequence Number Presence
	if crl.Number == nil {
		warnings = append(warnings, "CRL is missing the X.509 cRLNumber extension")
	}

	// Output Warnings
	if len(warnings) > 0 {
		fmt.Println(" Warnings:")
		for _, w := range warnings {
			fmt.Printf("  - %s\n", w)
		}
	}

	// Output Issues and handle exit criteria
	if len(issues) > 0 {
		fmt.Println("\n Validation Failed:")
		for _, issue := range issues {
			fmt.Printf("  - %s\n", issue)
		}
		return fmt.Errorf("crl validation failed with %d error(s)", len(issues))
	}

	fmt.Println(" All CRL sanity checks passed!")
	return nil
}
