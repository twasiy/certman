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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"
)

type InspectCmd struct {
	ID int64 `arg:"" help:"Database ID of the CRL to inspect."`
}

func (ic *InspectCmd) Run(ctx context.Context, query base.Querier) error {
	crlRecord, err := query.GetCRLByID(ctx, ic.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch CRL from DB: %w", err)
	}

	block, _ := pem.Decode([]byte(crlRecord.CrlPem))
	if block == nil {
		return errors.New("failed to decode CRL PEM block")
	}

	parsedCRL, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse x509 revocation list: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "CRL DOCUMENT INSPECTION")
	fmt.Fprintln(w, "=======================")
	fmt.Fprintf(w, "DB Record Name:\t%s\n", crlRecord.Name)
	fmt.Fprintf(w, "CRL Number:\t%s\n", parsedCRL.Number.String())
	fmt.Fprintf(w, "Signature Algo:\t%s\n", parsedCRL.SignatureAlgorithm.String())
	fmt.Fprintf(w, "This Update:\t%s\n", parsedCRL.ThisUpdate.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Next Update:\t%s\n", parsedCRL.NextUpdate.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Revoked Count:\t%d\n", len(parsedCRL.RevokedCertificateEntries))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "REVOKED CERTIFICATES LIST")
	fmt.Fprintln(w, "--------------------------------------------------------")
	fmt.Fprintln(w, "SERIAL NUMBER (HEX)\tREVOCATION TIME\tREASON CODE")
	fmt.Fprintln(w, "-------------------\t---------------\t-----------")

	if len(parsedCRL.RevokedCertificateEntries) == 0 {
		fmt.Fprintln(w, "(No entries found inside this CRL document)")
	} else {
		for _, rc := range parsedCRL.RevokedCertificateEntries {
			reasonCodeStr := "Unspecified"
			for _, ext := range rc.Extensions {
				if ext.Id.Equal([]int{2, 5, 29, 21}) && len(ext.Value) == 3 {
					reasonCodeStr = fmt.Sprintf("%d", ext.Value[2])
				}
			}

			fmt.Fprintf(w, "%X\t%s\t%s\n",
				rc.SerialNumber,
				rc.RevocationTime.Format("2006-01-02 15:04:05"),
				reasonCodeStr,
			)
		}
	}

	return w.Flush()
}
