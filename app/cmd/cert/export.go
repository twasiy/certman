package cert

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type ExportCmd struct {
	SerialNumber string `name:"sn" xor:"own" help:"Serial Number of the Certificate."`
	CommonName   string `name:"cn" xor:"own" help:"Common Name of the Certificate."`
	Path         string `name:"path" short:"p" type:"path" help:"Path to export the file. [file name must be omitted]"`
	Format       string `name:"format" short:"f" help:"Specific format to export (e.g.,pem,der)"`
}

func (ec *ExportCmd) Run(ctx context.Context, query base.Querier) error {
	var dbCert base.Certificate
	var err error

	if ec.SerialNumber != "" && ec.CommonName == "" {
		dbCert, err = query.GetCertificateBySN(ctx, ec.SerialNumber)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
	} else if ec.SerialNumber == "" && ec.CommonName != "" {
		dbCert, err = query.GetCertificateByCN(ctx, ec.CommonName)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
	} else {
		return errors.New("exactly one flag (--sn or --cn) must be provided")
	}

	ext := ".pem"
	if ec.Format == "der" {
		ext = ".der"
	}

	var filePath string
	baseName := utils.SanitizeFilename(dbCert.CommonName, "exported_certificate") + ext
	if ec.Path != "" {
		targetDir, err := utils.JoinHomeDir(ec.Path)
		if err != nil {
			return err
		}
		filePath = filepath.Join(targetDir, baseName)
	} else {
		filePath = baseName
	}

	if ec.Format == "pem" {
		err := os.WriteFile(filePath, []byte(dbCert.CertificatePem), 0o644)
		if err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
	} else {
		block, _ := pem.Decode([]byte(dbCert.CertificatePem))
		if block == nil {
			return errors.New("failed to decode PEM formatted Certificate")
		}
		err = os.WriteFile(filePath, block.Bytes, 0o644)
		if err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
	}

	return nil
}
