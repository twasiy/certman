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
	"crypto/x509"
	"fmt"
	"os"
	"pkit/app/cmd/helper"
	"pkit/app/utils"
	"pkit/db/base"
	"reflect"
	"strings"
	"text/tabwriter"
	"time"
)

type DiffCmd struct {
	ID1 int64 `arg:"" help:"Database ID of the first certificate to compare."`
	ID2 int64 `arg:"" help:"Database ID of the second certificate to compare."`
}

func (dc *DiffCmd) Run(ctx context.Context, query base.Querier) error {
	dbCert1, err := query.GetCertificateByID(ctx, dc.ID1)
	if err != nil {
		return fmt.Errorf("failed to fetch certificate ID %d: %w", dc.ID1, err)
	}
	dbCert2, err := query.GetCertificateByID(ctx, dc.ID2)
	if err != nil {
		return fmt.Errorf("failed to fetch certificate ID %d: %w", dc.ID2, err)
	}

	cert1, err := utils.ParseCertificate([]byte(dbCert1.CertificatePem))
	if err != nil {
		return fmt.Errorf("failed to parse certificate ID %d: %w", dc.ID1, err)
	}
	cert2, err := utils.ParseCertificate([]byte(dbCert2.CertificatePem))
	if err != nil {
		return fmt.Errorf("failed to parse certificate ID %d: %w", dc.ID2, err)
	}

	fmt.Printf("Comparing Certificate #%d [%s] vs Certificate #%d [%s]\n\n",
		dc.ID1, cert1.Subject.CommonName,
		dc.ID2, cert2.Subject.CommonName)

	diffs := compareCertificates(cert1, cert2)

	if len(diffs) == 0 {
		fmt.Println("Certificates are functionally identical across all X.509 parameters.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

	fmt.Fprintf(w, "FIELD\tCERT #%d\tCERT #%d\n", dc.ID1, dc.ID2)
	fmt.Fprintln(w, "-----\t--------\t--------")

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

func compareCertificates(c1, c2 *x509.Certificate) []FieldDiff {
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

	// Basic Metadata & Serial
	if c1.SerialNumber.Cmp(c2.SerialNumber) != 0 {
		addDiff("Serial Number", c1.SerialNumber.String(), c2.SerialNumber.String())
	}

	// Subject (pkix.Name)
	helper.ComparePkixName("Subject", c1.Subject, c2.Subject, addDiff)

	// Issuer (pkix.Name)
	helper.ComparePkixName("Issuer", c1.Issuer, c2.Issuer, addDiff)

	// Temporal Validity
	if !c1.NotBefore.Equal(c2.NotBefore) {
		addDiff("Valid From", c1.NotBefore.Format(time.RFC3339), c2.NotBefore.Format(time.RFC3339))
	}
	if !c1.NotAfter.Equal(c2.NotAfter) {
		addDiff("Valid Until", c1.NotAfter.Format(time.RFC3339), c2.NotAfter.Format(time.RFC3339))
	}

	// Algorithms & Public Key
	if c1.SignatureAlgorithm != c2.SignatureAlgorithm {
		addDiff("Sig Algorithm", c1.SignatureAlgorithm.String(), c2.SignatureAlgorithm.String())
	}
	if c1.PublicKeyAlgorithm != c2.PublicKeyAlgorithm {
		addDiff("Public Key Alg", c1.PublicKeyAlgorithm.String(), c2.PublicKeyAlgorithm.String())
	}

	// SANs (DNS, Email, IP, URI)
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

	// Key Usage & Extended Key Usage
	if c1.KeyUsage != c2.KeyUsage {
		addDiff("Key Usage", fmt.Sprintf("0x%x", c1.KeyUsage), fmt.Sprintf("0x%x", c2.KeyUsage))
	}
	if !reflect.DeepEqual(c1.ExtKeyUsage, c2.ExtKeyUsage) {
		addDiff("Ext Key Usage", fmt.Sprint(c1.ExtKeyUsage), fmt.Sprint(c2.ExtKeyUsage))
	}

	// Basic Constraints
	if c1.IsCA != c2.IsCA {
		addDiff("Is CA", fmt.Sprintf("%t", c1.IsCA), fmt.Sprintf("%t", c2.IsCA))
	}
	if c1.MaxPathLen != c2.MaxPathLen || c1.MaxPathLenZero != c2.MaxPathLenZero {
		addDiff("Max Path Length", fmt.Sprint(c1.MaxPathLen), fmt.Sprint(c2.MaxPathLen))
	}

	return diffs
}
