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
package key

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"pkit/utils"
	"pkit/db/base"
	"strings"
)

type ExportCmd struct {
	ID     int64  `arg:"" help:"Database ID of the key pair to export."`
	Path   string `name:"path" short:"p" help:"Destination directory or file path for the exported key pair."`
	Format string `name:"format" short:"f" default:"pem" help:"File format for the exported key pair (e.g., pem, der)."`
	Blob   bool   `name:"blob" short:"b" help:"Export the private key as an encrypted binary blob."`
}

func (ec *ExportCmd) Run(ctx context.Context, query base.Querier) error {
	key, err := query.GetKeyByID(ctx, ec.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch key from DB: %w", err)
	}

	format := strings.ToLower(strings.TrimSpace(ec.Format))
	if format == "" {
		format = "pem"
	}

	ext := ".pem"
	if format == "der" {
		ext = ".der"
	} else if format != "pem" {
		return fmt.Errorf("unsupported format '%s': expected 'pem' or 'der'", ec.Format)
	}

	privKeyFilePath, pubKeyFilePath, err := resolveKeyDestinationPaths(ec.Path, key.Name, ext)
	if err != nil {
		return fmt.Errorf("failed to resolve output path: %w", err)
	}

	targetDir := filepath.Dir(privKeyFilePath)
	if targetDir != "." && targetDir != "" {
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return fmt.Errorf("failed to create target directory %s: %w", targetDir, err)
		}
	}

	var privBytes, pubBytes []byte

	if format == "pem" {
		if !ec.Blob {
			decryptedPrivKey, err := utils.DecryptPrivateKey([]byte(key.PrivateKeyPem))
			if err != nil {
				return fmt.Errorf("failed to decrypt private key: %w", err)
			}
			privBytes = pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: decryptedPrivKey,
			})
		} else {
			privBytes = []byte(key.PrivateKeyPem)
		}
		pubBytes = []byte(key.PublicKeyPem)

	} else {
		if !ec.Blob {
			decryptedPrivKey, err := utils.DecryptPrivateKey([]byte(key.PrivateKeyPem))
			if err != nil {
				return fmt.Errorf("failed to decrypt private key: %w", err)
			}
			privBytes = decryptedPrivKey
		} else {
			privBlock, _ := pem.Decode([]byte(key.PrivateKeyPem))
			if privBlock == nil {
				return errors.New("failed to decode private key PEM into DER")
			}
			privBytes = privBlock.Bytes
		}

		pubBlock, _ := pem.Decode([]byte(key.PublicKeyPem))
		if pubBlock == nil {
			return errors.New("failed to decode public key PEM into DER")
		}
		pubBytes = pubBlock.Bytes
	}

	if err := os.WriteFile(privKeyFilePath, privBytes, 0o600); err != nil {
		return fmt.Errorf("failed to write private key to %s: %w", privKeyFilePath, err)
	}

	if err := os.WriteFile(pubKeyFilePath, pubBytes, 0o644); err != nil {
		return fmt.Errorf("failed to write public key to %s: %w", pubKeyFilePath, err)
	}

	fmt.Printf("Successfully exported Private Key to: %s\n", privKeyFilePath)
	fmt.Printf("Successfully exported Public Key to:  %s\n", pubKeyFilePath)
	return nil
}

// Helper to calculate output file paths for key pairs
func resolveKeyDestinationPaths(inputPath, keyName, ext string) (string, string, error) {
	sanitizedBase := utils.ToSnakeCase(utils.SanitizeFilename(keyName, "exported_key"))

	if inputPath == "" {
		privPath := sanitizedBase + "_private_key" + ext
		pubPath := sanitizedBase + "_public_key" + ext
		return privPath, pubPath, nil
	}

	resolvedPath, err := utils.JoinHomeDir(inputPath)
	if err != nil {
		return "", "", err
	}

	fi, err := os.Stat(resolvedPath)
	isDir := err == nil && fi.IsDir()

	if isDir || strings.HasSuffix(inputPath, "/") || strings.HasSuffix(inputPath, "\\") {
		privPath := filepath.Join(resolvedPath, sanitizedBase+"_private_key"+ext)
		pubPath := filepath.Join(resolvedPath, sanitizedBase+"_public_key"+ext)
		return privPath, pubPath, nil
	}

	dir := filepath.Dir(resolvedPath)
	baseName := filepath.Base(resolvedPath)

	if pathExt := filepath.Ext(baseName); pathExt != "" {
		baseName = strings.TrimSuffix(baseName, pathExt)
	}

	privPath := filepath.Join(dir, baseName+"_private_key"+ext)
	pubPath := filepath.Join(dir, baseName+"_public_key"+ext)

	return privPath, pubPath, nil
}
