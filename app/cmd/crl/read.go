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
	"certman/db/base"
	"context"
	"fmt"
	"os"
	"text/tabwriter"
)

type ReadCmd struct {
	ID int64 `arg:"" help:"Database ID of the CRL to display."`
}

func (rc *ReadCmd) Run(ctx context.Context, query base.Querier) error {
	crl, err := query.GetCRLByID(ctx, rc.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch CRL from DB: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "DATABASE RECORD METADATA")
	fmt.Fprintln(w, "------------------------")
	fmt.Fprintf(w, "ID:\t%d\n", crl.ID)
	fmt.Fprintf(w, "Name:\t%s\n", crl.Name)
	fmt.Fprintf(w, "CRL Number:\t%d\n", crl.CrlNumber)
	fmt.Fprintf(w, "Issuer ID:\t%d\n", crl.ID)
	fmt.Fprintf(w, "This Update:\t%s\n", crl.ThisUpdate.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Next Update:\t%s\n", crl.NextUpdate.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Created At:\t%s\n", crl.CreatedAt.Time.Format("2006-01-02 15:04:05"))

	fmt.Fprintln(w, "\nRAW PEM DATA")
	fmt.Fprintln(w, "------------")
	fmt.Fprintln(w, crl.CrlPem)

	return w.Flush()
}
