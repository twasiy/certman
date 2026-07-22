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
package chain

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"pkit/app/cmd/cert/exp/helper"
	"pkit/app/utils"
	"pkit/db/base"
)

type ChainCmd struct {
	ID     int64  `arg:"" help:"Database ID of the leaf certificate whose certificate chain to export."`
	Path   string `name:"path" type:"path" help:"Destination directory or file path for the exported chain."`
	Format string `name:"format" short:"f" required:"" enum:"pem,pkcs7" default:"pem" help:"File format for the exported chain."`
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
