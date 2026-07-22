package bundle

import (
	"certman/app/cmd/cert/exp/helper"
	"certman/app/utils"
	"certman/db/base"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"software.sslmate.com/src/go-pkcs12"
)

type BundleCmd struct {
	ID         int64  `arg:"" help:"ID of the Leaf Certificate to export the full bundle in PKCS#12 or pem format"`
	PassPhrase string `name:"pass-phrase" help:"Pass Phrase to Encrypt the Private keys. Only applicable for PKCS#12 format."`
	Path       string `name:"path" type:"path" help:"Path to Export the bundle file."`
	Format     string `name:"format" short:"f" required:"" enum:"pkcs12,pem" default:"pkcs12" help:"Format to export the bundle (pkcs12 or pem)."`
}

func (bc *BundleCmd) Run(ctx context.Context, query base.Querier) error {
	ext := ".p12"
	if bc.Format == "pem" {
		ext = ".pem"
	}

	var data []byte
	var err error

	dbCert, err := query.GetCertificateByID(ctx, bc.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch Certificate from DB: %w", err)
	}
	cert, err := utils.ParseCertificate([]byte(dbCert.CertificatePem))
	if err != nil {
		return err
	}

	privateKey, err := getPrivateKey(ctx, query, dbCert.KeyID)
	if err != nil {
		return err
	}

	chain, err := helper.GetCertificateChain(ctx, query, cert)
	if err != nil {
		return err
	}

	if bc.Format == "pkcs12" {
		data, err = pkcs12.Modern.Encode(privateKey, cert, chain, bc.PassPhrase)
		if err != nil {
			return fmt.Errorf("failed to encode PKCS#12 bundle: %w", err)
		}
	} else {
		data, err = GetPEMBundle(privateKey, cert, chain)
		if err != nil {
			return err
		}
	}

	defaultFileName := utils.SanitizeFilename(cert.Subject.CommonName, "bundle") + "_bundle" + ext
	outPath, err := utils.ResolveDestinationPath(bc.Path, defaultFileName, ext)
	if err != nil {
		return fmt.Errorf("failed to resolve target path: %w", err)
	}

	targetDir := filepath.Dir(outPath)
	if targetDir != "." && targetDir != "" {
		if err := os.MkdirAll(targetDir, 0o755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", targetDir, err)
		}
	}

	if err := os.WriteFile(outPath, data, 0o600); err != nil {
		return fmt.Errorf("failed to write bundle file to %s: %w", outPath, err)
	}

	log.Printf("Success: successfully written %s bundle file to: %s", bc.Format, outPath)
	return nil
}

func getPrivateKey(ctx context.Context, query base.Querier, keyID int64) (any, error) {
	keys, err := query.GetKeyByID(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Keys from DB: %w", err)
	}
	privateKey, _, err := utils.ParseKeys([]byte(keys.PrivateKeyPem), []byte(keys.PublicKeyPem))
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
