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
package cert

import (
	"context"
	"fmt"
	"pkit/app/utils"
	"pkit/db/base"
)

type ReadCmd struct {
	ID int64 `arg:"" help:"Database ID of the certificate to display."`
}

func (rc *ReadCmd) Run(ctx context.Context, query base.Querier) error {
	dbCert, err := query.GetCertificateByID(ctx, rc.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch certificate from DB: %w", err)
	}

	cert, err := utils.ParseCertificate([]byte(dbCert.CertificatePem))
	if err != nil {
		return err
	}

	fmt.Printf("\u2022 Serial Number: %s\n", cert.SerialNumber)
	fmt.Printf("\u2022 Common Name: %s\n", dbCert.CommonName)
	fmt.Printf("\u2022 Cert Type: %s\n", dbCert.Type)
	fmt.Printf("\n%s\n", dbCert.CertificatePem)

	return nil
}
