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
	"certman/app/cmd/helper"
	"certman/app/utils"
	"certman/db/base"
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"text/tabwriter"
	"time"
)

type DiffCmd struct {
	ID1 int64 `arg:"" help:"Database ID of the first CRL to compare."`
	ID2 int64 `arg:"" help:"Database ID of the second CRL to compare."`
}

func (dc *DiffCmd) Run(ctx context.Context, query base.Querier) error {
	dbCRL1, err := query.GetCRLByID(ctx, dc.ID1)
	if err != nil {
		return fmt.Errorf("failed to fetch CRL ID %d: %w", dc.ID1, err)
	}

	dbCRL2, err := query.GetCRLByID(ctx, dc.ID2)
	if err != nil {
		return fmt.Errorf("failed to fetch CRL ID %d: %w", dc.ID2, err)
	}

	crl1, err := utils.ParseCRL([]byte(dbCRL1.CrlPem))
	if err != nil {
		return fmt.Errorf("failed to parse CRL ID %d: %w", dc.ID1, err)
	}

	crl2, err := utils.ParseCRL([]byte(dbCRL2.CrlPem))
	if err != nil {
		return fmt.Errorf("failed to parse CRL ID %d: %w", dc.ID2, err)
	}

	fmt.Printf("Comparing CRL #%d [%s] vs CRL #%d [%s]\n\n",
		dc.ID1, dbCRL1.Name,
		dc.ID2, dbCRL2.Name)

	diffs := compareCRLs(crl1, crl2)

	if len(diffs) == 0 {
		fmt.Println("CRLs are functionally identical across all X.509 parameters.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

	fmt.Fprintf(w, "FIELD\tCRL #%d\tCRL #%d\n", dc.ID1, dc.ID2)
	fmt.Fprintln(w, "-----\t------\t------")

	for _, diff := range diffs {
		fmt.Fprintf(w, "%s\t%s\t%s\n", diff.Field, diff.Val1, diff.Val2)
	}

	return w.Flush()
}

type FieldDiff struct {
	Field string
	Val1  string
	Val2  string
}

func compareCRLs(c1, c2 *x509.RevocationList) []FieldDiff {
	var diffs []FieldDiff

	addDiff := func(field, val1, val2 string) {
		if val1 == "" {
			val1 = "<none>"
		}
		if val2 == "" {
			val2 = "<none>"
		}
		diffs = append(diffs, FieldDiff{Field: field, Val1: val1, Val2: val2})
	}

	// CRL Number Comparison
	c1Num := "<none>"
	if c1.Number != nil {
		c1Num = c1.Number.String()
	}
	c2Num := "<none>"
	if c2.Number != nil {
		c2Num = c2.Number.String()
	}
	if c1Num != c2Num {
		addDiff("CRL Number", c1Num, c2Num)
	}

	// Issuer Details
	helper.ComparePkixName("Issuer", c1.Issuer, c2.Issuer, addDiff)

	// Update Timestamps
	if !c1.ThisUpdate.Equal(c2.ThisUpdate) {
		addDiff("This Update", c1.ThisUpdate.Format(time.RFC3339), c2.ThisUpdate.Format(time.RFC3339))
	}
	if !c1.NextUpdate.Equal(c2.NextUpdate) {
		addDiff("Next Update", c1.NextUpdate.Format(time.RFC3339), c2.NextUpdate.Format(time.RFC3339))
	}

	// Cryptographic Algorithms
	if c1.SignatureAlgorithm != c2.SignatureAlgorithm {
		addDiff("Sig Algorithm", c1.SignatureAlgorithm.String(), c2.SignatureAlgorithm.String())
	}

	// Revoked Certificates Count & Differences
	if len(c1.RevokedCertificateEntries) != len(c2.RevokedCertificateEntries) {
		addDiff("Revoked Count",
			fmt.Sprintf("%d entry(ies)", len(c1.RevokedCertificateEntries)),
			fmt.Sprintf("%d entry(ies)", len(c2.RevokedCertificateEntries)))
	}

	// Detailed Revocation Delta
	diffRevokedEntries(c1.RevokedCertificateEntries, c2.RevokedCertificateEntries, addDiff)

	return diffs
}

func diffRevokedEntries(entries1, entries2 []x509.RevocationListEntry, addDiff func(string, string, string)) {
	m1 := make(map[string]x509.RevocationListEntry)
	for _, entry := range entries1 {
		m1[fmt.Sprintf("%X", entry.SerialNumber)] = entry
	}

	m2 := make(map[string]x509.RevocationListEntry)
	for _, entry := range entries2 {
		m2[fmt.Sprintf("%X", entry.SerialNumber)] = entry
	}

	// Detect added serials
	for serial := range m2 {
		if _, exists := m1[serial]; !exists {
			addDiff(fmt.Sprintf("Revoked Serial [%s]", serial), "<not present>", "Present")
		}
	}

	// Detect removed serials
	for serial := range m1 {
		if _, exists := m2[serial]; !exists {
			addDiff(fmt.Sprintf("Revoked Serial [%s]", serial), "Present", "<not present>")
		}
	}
}
