package crl

import (
	"certman/db/base"
	"context"
	"fmt"
	"os"
	"text/tabwriter"
)

type ReadCmd struct {
	CRLName string `name:"crl-name" aliases:"crl" help:"DB recorded CRL Name."`
}

func (rc *ReadCmd) Run(ctx context.Context, query base.Querier) error {
	crl, err := query.GetCRLByName(ctx, rc.CRLName)
	if err != nil {
		return fmt.Errorf("failed to get crl: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "DATABASE RECORD METADATA")
	fmt.Fprintln(w, "------------------------")
	fmt.Fprintf(w, "ID:\t%d\n", crl.ID)
	fmt.Fprintf(w, "Name:\t%s\n", crl.Name)
	fmt.Fprintf(w, "CRL Number:\t%d\n", crl.CrlNumber)
	fmt.Fprintf(w, "Issuer Serial:\t%s\n", crl.IssuerSerialNumber)
	fmt.Fprintf(w, "This Update:\t%s\n", crl.ThisUpdate.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Next Update:\t%s\n", crl.NextUpdate.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Created At:\t%s\n", crl.CreatedAt.Time.Format("2006-01-02 15:04:05"))

	fmt.Fprintln(w, "\nRAW PEM DATA")
	fmt.Fprintln(w, "------------")
	fmt.Fprintln(w, crl.CrlPem)

	return w.Flush()
}
