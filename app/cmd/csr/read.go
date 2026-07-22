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
	"context"
	"fmt"
	"pkit/db/base"
	"strings"
)

type ReadCmd struct {
	ID int64 `arg:"" help:"Database ID of the CSR to display."`
}

func (rc *ReadCmd) Run(ctx context.Context, query base.Querier) error {
	dbCsr, err := query.GetCSRByID(ctx, rc.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch CSR from DB: %w", err)
	}

	pemData := strings.TrimSpace(dbCsr.CsrPem)
	if pemData == "" {
		return fmt.Errorf("CSR #%d contains no PEM data", rc.ID)
	}

	fmt.Println(pemData)
	return nil
}
