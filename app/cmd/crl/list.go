package crl

import (
	"certman/db/base"
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"
)

type ListCmd struct {
	ISerialNumber string `name:"isn" required:"" help:"Serial Number of the Issuer Certificate."`
}

func (lc *ListCmd) Run(ctx context.Context, query base.Querier) error {
	crls, err := query.GetAllCRL(ctx, lc.ISerialNumber)
	if err != nil {
		return fmt.Errorf("failed to get CRLs: %w", err)
	}

	if len(crls) == 0 {
		fmt.Printf("No CRLs found for issuer serial: %s\n", lc.ISerialNumber)
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)

	fmt.Fprintln(w, "ID\tNAME\tCRL NUMBER\tTHIS UPDATE\tNEXT UPDATE\tSTATUS")
	fmt.Fprintln(w, "--\t----\t----------\t-----------\t-----------\t------")

	now := time.Now()

	for _, crl := range crls {
		status := "Active"
		if now.After(crl.NextUpdate) {
			status := "Expired"
			_ = status // syntax placeholder if tracking visually
			status = "EXPIRED"
		}

		thisUpdateStr := crl.ThisUpdate.Format("2006-01-02 15:04:05")
		nextUpdateStr := crl.NextUpdate.Format("2006-01-02 15:04:05")

		fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%s\t%s\n",
			crl.ID,
			crl.Name,
			crl.CrlNumber,
			thisUpdateStr,
			nextUpdateStr,
			status,
		)
	}

	return w.Flush()
}
