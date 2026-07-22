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
	"certman/app/utils"
	"certman/db/base"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"
)

type ValidateCmd struct {
	ID int64 `arg:"" help:"Database ID of the certificate to validate."`
}

func (vc *ValidateCmd) Run(ctx context.Context, query base.Querier) error {
	dbCert, err := query.GetCertificateByID(ctx, vc.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch certificate from DB: %w", err)
	}

	cert, err := utils.ParseCertificate([]byte(dbCert.CertificatePem))
	if err != nil {
		return err
	}

	fmt.Printf("Validating Certificate ID %d [%s]...\n\n", vc.ID, cert.Subject.CommonName)

	var issues []string
	var warnings []string

	now := time.Now()
	if now.Before(cert.NotBefore) {
		issues = append(issues, fmt.Sprintf("Not active yet (Valid starting: %s)", cert.NotBefore.Format("2006-01-02 15:04:05 UTC")))
	} else if now.After(cert.NotAfter) {
		issues = append(issues, fmt.Sprintf("Expired on %s", cert.NotAfter.Format("2006-01-02 15:04:05 UTC")))
	} else {
		// Non-fatal warning if expiring soon
		daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
		if daysRemaining <= 30 {
			warnings = append(warnings, fmt.Sprintf("Certificate expires soon (%d days remaining)", daysRemaining))
		}
	}

	switch cert.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		issues = append(issues, fmt.Sprintf("Insecure signature algorithm used: %s", cert.SignatureAlgorithm))
	}

	if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		keySize := rsaKey.N.BitLen()
		if keySize < 2048 {
			issues = append(issues, fmt.Sprintf("Weak RSA key length (%d bits; minimum required is 2048 bits)", keySize))
		}
	}

	if !cert.IsCA && len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
		warnings = append(warnings, "Certificate lacks SANs (DNSNames/IPAddresses); modern browsers require SAN entries")
	}

	if len(warnings) > 0 {
		fmt.Println(" Warnings:")
		for _, w := range warnings {
			fmt.Printf("  - %s\n", w)
		}
	}

	if len(issues) > 0 {
		fmt.Println("\n Validation Failed:")
		for _, issue := range issues {
			fmt.Printf("  - %s\n", issue)
		}
		return fmt.Errorf("certificate validation failed with %d error(s)", len(issues))
	}

	fmt.Println(" All certificate sanity checks passed!")
	return nil
}
