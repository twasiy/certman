package cmd

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
	Cert ExportCertCmd `cmd:"" help:"Exports Certificates in different formats (e.g.,pem, der)."`
	Key  ExportKeyCmd  `cmd:"" help:"Exports public/private key in different formats (e.g.,pem,der)."`
}

type ExportCertCmd struct {
	SerialNumber string `name:"sn" help:"Serial Number of the Certificate. Either one can be selected."`
	CommonName   string `name:"cn" help:"Common Name of the Certificate. Either one can be selected"`
	Path         string `name:"path" short:"p" type:"path" help:"Path to export the file."`
	Format       string `name:"format" short:"f" help:"Specific format to export (e.g.,pem,der)"`
}

func (ecc *ExportCertCmd) Run(ctx context.Context, query base.Querier) error {
	var cert base.Certificate
	var err error

	if ecc.SerialNumber != "" && ecc.CommonName == "" {
		cert, err = query.GetCertBySN(ctx, ecc.SerialNumber)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
	} else if ecc.SerialNumber == "" && ecc.CommonName != "" {
		cert, err = query.GetCertByCN(ctx, ecc.CommonName)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
	} else {
		return errors.New("One flag can be selected at a time")
	}

	ext := ".pem"
	if ecc.Format == "der" {
		ext = ".der"
	}

	filePath := cert.CommonName + ext
	if ecc.Path != "" {
		filePath, err = utils.JoinHomeDir(ecc.Path)
		if err != nil {
			return err
		}
	}

	if ecc.Format == "pem" {
		err := os.WriteFile(filePath, []byte(cert.CertificatePem), 0o644)
		if err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
	} else {
		block, _ := pem.Decode([]byte(cert.CertificatePem))
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

type ExportKeyCmd struct {
	Name   string `name:"key-name" aliases:"key" required:"" help:"Name of the Key Pair."`
	Path   string `name:"path" short:"p" type:"path" help:"Path to export the file. [file name must be omitted]."`
	Format string `name:"format" short:"f" help:"Specific format to export (e.g.,pem,der)"`
	blob   bool   `name:"blob" short:"b" help:"If selected private key will be exported as encrypted blob encoded into PEM."`
}

func (ekc *ExportKeyCmd) Run(ctx context.Context, query base.Querier) error {
	key, err := query.GetKeyByName(ctx, ekc.Name)
	if err != nil {
		return fmt.Errorf("failed to get key: %w", err)
	}

	ext := ".pem"
	if ekc.Format == "der" {
		ext = ".der"
	}

	var tempPath string
	if ekc.Path != "" {
		tempPath, err = utils.JoinHomeDir(ekc.Path)
		if err != nil {
			return err
		}
	}
	privKeyFilePath := filepath.Join(tempPath, utils.ToSnakeCase(key.Name)+"_private_key"+ext)
	pubKeyFilePath := filepath.Join(tempPath, utils.ToSnakeCase(key.Name)+"_public_key"+ext)

	if ekc.Format == "pem" {
		if !ekc.blob {
			decryptedPrivKey, err := DecryptPrivKey([]byte(key.PrivateKeyPem))
			if err != nil {
				return err
			}
			privPemBytes := pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: decryptedPrivKey,
			})
			err = os.WriteFile(privKeyFilePath, privPemBytes, 0o600)
			if err != nil {
				return fmt.Errorf("failed to write private key: %w", err)
			}
		} else {
			err = os.WriteFile(privKeyFilePath, []byte(key.PrivateKeyPem), 0o600)
			if err != nil {
				return fmt.Errorf("failed to write private key: %w", err)
			}
		}

		err = os.WriteFile(pubKeyFilePath, []byte(key.PublicKeyPem), 0o644)
		if err != nil {
			return fmt.Errorf("failed to write public key: %w", err)
		}

	} else {

		if !ekc.blob {
			decryptedPrivKey, err := DecryptPrivKey([]byte(key.PrivateKeyPem))
			if err != nil {
				return err
			}
			err = os.WriteFile(privKeyFilePath, decryptedPrivKey, 0o600)
			if err != nil {
				return fmt.Errorf("failed to write private key: %w", err)
			}
		} else {
			privBlock, _ := pem.Decode([]byte(key.PrivateKeyPem))
			if privBlock == nil {
				return errors.New("failed to decode private key")
			}
			err = os.WriteFile(privKeyFilePath, privBlock.Bytes, 0o600)
			if err != nil {
				return fmt.Errorf("failed to write private key: %w", err)
			}
		}

		pubBlock, _ := pem.Decode([]byte(key.PublicKeyPem))
		if pubBlock == nil {
			return errors.New("failed ot decode public key")
		}
		err = os.WriteFile(pubKeyFilePath, pubBlock.Bytes, 0o644)
		if err != nil {
			return fmt.Errorf("failed to write public key: %w", err)
		}
	}

	return nil
}
