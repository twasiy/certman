package cert

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

type VerifyCmd struct {
	SerialNumber string `name:"sn" xor:"own" help:"Serial Number of the Certificate."`
	CommonName   string `name:"cn" xor:"own" help:"Common Name of the Certificate."`
}

func (vc *VerifyCmd) Run(ctx context.Context, query base.Querier) error {
	currentDBCert, err := vc.fetchCertificate(ctx, query)
	if err != nil {
		return err
	}

	currentX509, err := utils.ParseCertificate([]byte(currentDBCert.CertificatePem))
	if err != nil {
		return fmt.Errorf("failed to parse target certificate: %w", err)
	}

	// Build and walk the trust chain upward using AKID -> SKID pointers
	chain := []*x509.Certificate{currentX509}
	workingCert := currentX509

	fmt.Println("Building and verifying trust chain...")

	for {
		if workingCert.Subject.String() == workingCert.Issuer.String() {
			fmt.Printf("  └─ Root Anchor Found: %s\n", workingCert.Subject.CommonName)
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

		parentX509, err := utils.ParseCertificate([]byte(parentDBCert.CertificatePem))
		if err != nil {
			return fmt.Errorf("failed to parse parent certificate: %w", err)
		}

		if err := workingCert.CheckSignatureFrom(parentX509); err != nil {
			return fmt.Errorf("Verification Failed: Cryptographic signature mismatch between %s and issuer %s: %w", workingCert.Subject.CommonName, parentX509.Subject.CommonName, err)
		}

		fmt.Printf("  ├─ Verified signature by: %s\n", parentX509.Subject.CommonName)

		chain = append(chain, parentX509)
		workingCert = parentX509
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

func (vc *VerifyCmd) fetchCertificate(ctx context.Context, query base.Querier) (*base.Certificate, error) {
	if vc.SerialNumber != "" && vc.CommonName == "" {
		dbCert, err := query.GetCertificateBySN(ctx, vc.SerialNumber)
		if err != nil {
			return nil, fmt.Errorf("failed to get Certificate by SN: %w", err)
		}
		return &dbCert, nil
	} else if vc.SerialNumber == "" && vc.CommonName != "" {
		dbCert, err := query.GetCertificateByCN(ctx, vc.CommonName)
		if err != nil {
			return nil, fmt.Errorf("failed to get Certificate by CN: %w", err)
		}
		return &dbCert, nil
	}
	return nil, errors.New("exactly one flag (--sn or --cn) must be provided")
}
