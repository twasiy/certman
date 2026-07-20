package cert

import (
	_db_ "certman/db"
	"certman/db/base"
	"context"
	"database/sql"
	"fmt"
	"os"
	"text/tabwriter"
	"time"
)

type ListCmd struct {
	Limit  int `name:"limit" short:"l" help:"Limit specifies how many keys to show. if not given then it will show everything."`
	Offset int `name:"offset" short:"o" help:"Skip first N Certificates."`
}

func (lc *ListCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	var certs []base.ListCertificatesRow
	var err error

	if lc.Limit == 0 && lc.Offset == 0 {
		err = _db_.RunInTx(ctx, db, func(txQuerier base.Querier) error {
			count, err := txQuerier.TotalCertificates(ctx)
			if err != nil {
				return fmt.Errorf("failed to calculate total Certificates: %w", err)
			}
			certs, err = txQuerier.ListCertificates(ctx, base.ListCertificatesParams{Limit: count, Offset: 0})
			if err != nil {
				return fmt.Errorf("failed to list Certificates: %w", err)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("transaction failed, data rolled back: %w", err)
		}
	} else {
		certs, err = query.ListCertificates(ctx, base.ListCertificatesParams{Limit: int64(lc.Limit), Offset: int64(lc.Offset)})
		if err != nil {
			return fmt.Errorf("failed to list the certificates: %w", err)
		}
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)

	fmt.Fprintln(w, "SERIAL NUMBER\tCOMMON NAME\tTYPE\tSTATUS")
	fmt.Fprintln(w, "-----\t-----------\t----\t------")

	now := time.Now()

	for _, cert := range certs {
		status := "Active"

		if cert.IsRevoked.Valid && cert.IsRevoked.Int64 == 1 {
			status = "REVOKED"
		} else if now.After(cert.NotAfter) {
			status = "EXPIRED"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			cert.SerialNumber,
			cert.CommonName,
			cert.Type,
			status,
		)
	}

	return w.Flush()
}
