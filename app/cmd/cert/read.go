package cert

import (
	"certman/db/base"
	"context"
	"errors"
	"fmt"
)

type ReadCmd struct {
	SerialNumber string `name:"sn" xor:"own" help:"Serial Number of the Certificate."`
	CommonName   string `name:"cn" xor:"own" help:"Common Name of the Certificate."`
}

func (rc *ReadCmd) Run(ctx context.Context, query base.Querier) error {
	var cert base.Certificate
	var err error

	if rc.SerialNumber != "" && rc.CommonName == "" {
		cert, err = query.GetCertificateBySN(ctx, rc.SerialNumber)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
	} else if rc.SerialNumber == "" && rc.CommonName != "" {
		cert, err = query.GetCertificateByCN(ctx, rc.CommonName)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
	} else {
		return errors.New("exactly one flag (--sn or --cn) must be provided")
	}

	fmt.Printf("\u2022 Serial Number: %s\n", cert.SerialNumber)
	fmt.Printf("\u2022 Common Name: %s\n", cert.CommonName)
	fmt.Printf("\u2022 Cert Type: %s\n", cert.Type)
	fmt.Printf("\n%s\n", cert.CertificatePem)

	return nil
}
