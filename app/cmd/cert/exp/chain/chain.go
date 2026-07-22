package chain

import (
	"certman/app/cmd/cert/exp/helper"
	"certman/app/utils"
	"certman/db/base"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

type ChainCmd struct {
	ID     int64  `arg:"" help:"ID of the Leaf Certificate to export the full chain."`
	Path   string `name:"path" type:"path" help:"Path to export the chain file."`
	Format string `name:"format" short:"f" required:"" enum:"pem,pkcs7" default:"pem" help:"Format to export the chain (pem or pkcs7)."`
}

func (cc *ChainCmd) Run(ctx context.Context, query base.Querier) error {
	ext := ".pem"
	if cc.Format == "pkcs7" {
		ext = ".p7b"
	}

	dbCert, err := query.GetCertificateByID(ctx, cc.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch Certificate from DB: %w", err)
	}

	cert, err := utils.ParseCertificate([]byte(dbCert.CertificatePem))
	if err != nil {
		return err
	}

	chain, err := helper.GetCertificateChain(ctx, query, cert)
	if err != nil {
		return err
	}

	var data []byte
	if cc.Format == "pkcs7" {
		data, err = GetPKCS7Chain(cert, chain)
		if err != nil {
			return err
		}
	} else {
		data, err = GetPEMChain(cert, chain)
		if err != nil {
			return err
		}
	}

	defaultFileName := utils.SanitizeFilename(cert.Subject.CommonName, "chain") + "_chain" + ext
	outPath, err := utils.ResolveDestinationPath(cc.Path, defaultFileName, ext)
	if err != nil {
		return fmt.Errorf("failed to resolve target path: %w", err)
	}

	targetDir := filepath.Dir(outPath)
	if targetDir != "." && targetDir != "" {
		if err := os.MkdirAll(targetDir, 0o755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", targetDir, err)
		}
	}

	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		return fmt.Errorf("failed to write chain file to %s: %w", outPath, err)
	}

	log.Printf("Success: successfully written %s certificate chain to: %s", cc.Format, outPath)

	return nil
}
