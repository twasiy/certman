package key

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
	Name   string `name:"key-name" aliases:"key" required:"" help:"Name of the Key Pair."`
	Path   string `name:"path" short:"p" type:"path" help:"Path to export the file. [file name must be omitted]"`
	Format string `name:"format" short:"f" help:"Specific format to export (e.g.,pem,der)"`
	Blob   bool   `name:"blob" short:"b" help:"If selected private key will be exported as encrypted blob encoded into PEM."`
}

func (ec *ExportCmd) Run(ctx context.Context, query base.Querier) error {
	key, err := query.GetKeyByName(ctx, ec.Name)
	if err != nil {
		return fmt.Errorf("failed to get key: %w", err)
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
	privKeyFilePath := filepath.Join(tempPath,
		utils.ToSnakeCase(
			utils.SanitizeFilename(key.Name, "exported_private_key"))+"_private_key"+ext,
	)
	pubKeyFilePath := filepath.Join(tempPath,
		utils.ToSnakeCase(
			utils.SanitizeFilename(key.Name, "exported_public_key"))+"_public_key"+ext,
	)

	if ec.Format == "pem" {
		if !ec.Blob {
			decryptedPrivKey, err := utils.DecryptPrivKey([]byte(key.PrivateKeyPem))
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

		if !ec.Blob {
			decryptedPrivKey, err := utils.DecryptPrivKey([]byte(key.PrivateKeyPem))
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
			return errors.New("failed to decode public key")
		}
		err = os.WriteFile(pubKeyFilePath, pubBlock.Bytes, 0o644)
		if err != nil {
			return fmt.Errorf("failed to write public key: %w", err)
		}
	}

	return nil
}
