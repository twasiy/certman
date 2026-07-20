package crl

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"fmt"
	"time"
)

type VerifyCmd struct {
	CRLName string `name:"crl-name" aliases:"crl" help:"DB recorded CRL Name."`
}

func (vc *VerifyCmd) Run(ctx context.Context, query base.Querier) error {
	crlRecord, err := query.GetCRLByName(ctx, vc.CRLName)
	if err != nil {
		return fmt.Errorf("failed to get crl: %w", err)
	}

	issuerDBCert, err := query.GetCertificateBySN(ctx, crlRecord.IssuerSerialNumber)
	if err != nil {
		return fmt.Errorf("failed to get issuer certificate (%s) for verification: %w", crlRecord.IssuerSerialNumber, err)
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
