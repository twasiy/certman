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
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"pkit/app/cmd/helper"
	"pkit/app/utils"
	"pkit/db/base"
	"reflect"
	"strings"
	"text/tabwriter"
)

type DiffCmd struct {
	ID1 int64 `arg:"" help:"Database ID of the first CSR to compare."`
	ID2 int64 `arg:"" help:"Database ID of the second CSR to compare."`
}

func (dc *DiffCmd) Run(ctx context.Context, query base.Querier) error {
	dbCsr1, err := query.GetCSRByID(ctx, dc.ID1)
	if err != nil {
		return fmt.Errorf("failed to fetch CSR ID %d: %w", dc.ID1, err)
	}
	dbCsr2, err := query.GetCSRByID(ctx, dc.ID2)
	if err != nil {
		return fmt.Errorf("failed to fetch CSR ID %d: %w", dc.ID2, err)
	}

	csr1, err := utils.ParseCSR(dbCsr1.CsrPem)
	if err != nil {
		return fmt.Errorf("failed to parse CSR ID %d: %w", dc.ID1, err)
	}
	csr2, err := utils.ParseCSR(dbCsr2.CsrPem)
	if err != nil {
		return fmt.Errorf("failed to parse CSR ID %d: %w", dc.ID2, err)
	}

	fmt.Printf("Comparing CSR #%d [%s] vs CSR #%d [%s]\n\n",
		dc.ID1, csr1.Subject.CommonName,
		dc.ID2, csr2.Subject.CommonName)

	diffs := compareCSRs(csr1, csr2)

	if len(diffs) == 0 {
		fmt.Println("CSRs are functionally identical across all X.509 fields.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "FIELD\tCSR #%d\tCSR #%d\n", dc.ID1, dc.ID2)
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

func compareCSRs(c1, c2 *x509.CertificateRequest) []FieldDiff {
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

	// Subject Details
	helper.ComparePkixName("Subject", c1.Subject, c2.Subject, addDiff)

	// Signature & Public Key Algorithms
	if c1.SignatureAlgorithm != c2.SignatureAlgorithm {
		addDiff("Sig Algorithm", c1.SignatureAlgorithm.String(), c2.SignatureAlgorithm.String())
	}

	k1 := formatPubKey(c1.PublicKey)
	k2 := formatPubKey(c2.PublicKey)
	if k1 != k2 {
		addDiff("Public Key", k1, k2)
	}

	// SAN Comparisons
	if !reflect.DeepEqual(c1.DNSNames, c2.DNSNames) {
		addDiff("SAN: DNS Names", strings.Join(c1.DNSNames, ", "), strings.Join(c2.DNSNames, ", "))
	}
	if !reflect.DeepEqual(c1.EmailAddresses, c2.EmailAddresses) {
		addDiff("SAN: Email Addrs", strings.Join(c1.EmailAddresses, ", "), strings.Join(c2.EmailAddresses, ", "))
	}
	if !utils.IpSlicesEqual(c1.IPAddresses, c2.IPAddresses) {
		addDiff("SAN: IP Addresses", utils.FormatIPs(c1.IPAddresses), utils.FormatIPs(c2.IPAddresses))
	}
	if !utils.UriSlicesEqual(c1.URIs, c2.URIs) {
		addDiff("SAN: URIs", utils.FormatURIs(c1.URIs), utils.FormatURIs(c2.URIs))
	}

	return diffs
}

func formatPubKey(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA (%d bits)", k.N.BitLen())
	default:
		return fmt.Sprintf("%T", pub)
	}
}
