package crl

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
	CRLName string `name:"crl-name" aliases:"crl" help:"DB recorded CRL Name."`
	Path    string `name:"path" short:"p" type:"path" help:"Path to export the file. [file name must be omitted]"`
	Format  string `name:"format" short:"f" help:"Specific format to export (e.g., pem, der)"`
}

func (ec *ExportCmd) Run(ctx context.Context, query base.Querier) error {
	crl, err := query.GetCRLByName(ctx, ec.CRLName)
	if err != nil {
		return fmt.Errorf("could not get crl: %w", err)
	}

	ext := ".pem"
	if ec.Format == "der" {
		ext = ".der"
	}

	var tempPath string
	if ec.Path != "" {
		tempPath, err = utils.JoinHomeDir(ec.Path)
		if err != nil {
			return err
		}
	}

	crlFilePath := filepath.Join(tempPath, utils.SanitizeFilename(ec.CRLName, "exported_crl")+ext)

	if ec.Format == "der" {
		block, _ := pem.Decode([]byte(crl.CrlPem))
		if block == nil {
			return errors.New("failed to decode pem block")
		}
		err = os.WriteFile(crlFilePath, block.Bytes, 0o644)
		if err != nil {
			return fmt.Errorf("could not write to the file: %w", err)
		}
	} else {
		err = os.WriteFile(crlFilePath, []byte(crl.CrlPem), 0o644)
		if err != nil {
			return fmt.Errorf("could not write to the file: %w", err)
		}
	}

	fmt.Printf("Successfully exported CRL to: %s\n", crlFilePath)
	return nil
}
