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
package crl

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"pkit/app/utils"
	"pkit/db/base"
	"strings"
)

type ExportCmd struct {
	ID     int64  `arg:"" help:"Database ID of the CRL to export."`
	Path   string `name:"path" short:"p" help:"Destination directory or file path for the exported CRL."`
	Format string `name:"format" short:"f" default:"pem" help:"File format for the exported CRL (e.g., pem, der)."`
}

func (ec *ExportCmd) Run(ctx context.Context, query base.Querier) error {
	crl, err := query.GetCRLByID(ctx, ec.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch CRL from DB: %w", err)
	}

	format := strings.ToLower(strings.TrimSpace(ec.Format))
	if format == "" {
		format = "pem"
	}

	var data []byte
	var ext string

	switch format {
	case "pem":
		ext = ".pem"
		data = []byte(crl.CrlPem)

	case "der":
		ext = ".der"
		block, _ := pem.Decode([]byte(crl.CrlPem))
		if block == nil {
			return errors.New("failed to decode PEM block into DER")
		}
		data = block.Bytes

	default:
		return fmt.Errorf("unsupported format '%s': expected 'pem' or 'der'", ec.Format)
	}

	crlFilePath, err := utils.ResolveDestinationPath(ec.Path, crl.Name, ext)
	if err != nil {
		return fmt.Errorf("failed to resolve target path: %w", err)
	}

	targetDir := filepath.Dir(crlFilePath)
	if targetDir != "." && targetDir != "" {
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return fmt.Errorf("failed to create target directory %s: %w", targetDir, err)
		}
	}

	if err := os.WriteFile(crlFilePath, data, 0o644); err != nil {
		return fmt.Errorf("failed to write to file %s: %w", crlFilePath, err)
	}

	fmt.Printf("Successfully exported CRL to: %s\n", crlFilePath)
	return nil
}
