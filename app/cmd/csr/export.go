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
package csr

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ExportCmd struct {
	ID     int64  `arg:"" help:"Database ID of the CSR to export."`
	Path   string `name:"path" short:"p" help:"Destination directory or file path for the exported CSR."`
	Format string `name:"format" short:"f" default:"pem" help:"File format for the exported CSR (e.g., pem, der)."`
}

func (ec *ExportCmd) Run(ctx context.Context, query base.Querier) error {
	dbCsr, err := query.GetCSRByID(ctx, ec.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch CSR from DB: %w", err)
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
		data = []byte(dbCsr.CsrPem)

	case "der":
		ext = ".der"
		block, _ := pem.Decode([]byte(dbCsr.CsrPem))
		if block == nil {
			return errors.New("failed to decode PEM block into DER")
		}
		data = block.Bytes

	default:
		return fmt.Errorf("unsupported format '%s': expected 'pem' or 'der'", ec.Format)
	}

	csrFilePath, err := utils.ResolveDestinationPath(ec.Path, dbCsr.CommonName, ext)
	if err != nil {
		return fmt.Errorf("failed to resolve target path: %w", err)
	}

	targetDir := filepath.Dir(csrFilePath)
	if targetDir != "." && targetDir != "" {
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return fmt.Errorf("failed to create target directory %s: %w", targetDir, err)
		}
	}

	if err := os.WriteFile(csrFilePath, data, 0o644); err != nil {
		return fmt.Errorf("failed to write to file %s: %w", csrFilePath, err)
	}

	fmt.Printf("Successfully exported CSR to: %s\n", csrFilePath)
	return nil
}
