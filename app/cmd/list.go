package cmd

import (
	_db_ "certman/db"
	"certman/db/base"
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type ListCmd struct {
	Cert ListCertCmd `cmd:"" help:"Lists all the Certificates."`
	Key  ListKeyCmd  `cmd:"" help:"Lists all the Keys."`
}

type ListCertCmd struct {
	Limit  int `name:"limit" short:"l" help:"Limit specifies how many keys to show. if not given then it will show everything."`
	Offset int `name:"offset" short:"o" help:"Skip first N Certificates."`
}

func (lcc *ListCertCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	var certs []base.ListCertificatesRow
	var err error

	if lcc.Limit == 0 && lcc.Offset == 0 {
		err = _db_.RunInTx(ctx, db, func(txQuerier base.Querier) error {
			count, err := txQuerier.TotalCerts(ctx)
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
		certs, err = query.ListCertificates(ctx, base.ListCertificatesParams{Limit: int64(lcc.Limit), Offset: int64(lcc.Offset)})
		if err != nil {
			return fmt.Errorf("failed to list the certificates: %w", err)
		}
	}

	// NOTE: Have to use a library for showing table on terminal
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("|  %s |  %s  |\n", "Serial Number", "Common Name")
	fmt.Println(strings.Repeat("-", 50))
	for _, cert := range certs {
		fmt.Printf("|  %s  |  %s  |\n", cert.SerialNumber, cert.CommonName)
		fmt.Println(strings.Repeat("-", 50))
	}

	return nil
}

type ListKeyCmd struct {
	Limit  int `name:"limit" short:"l" help:"Limit specifies how many keys to show. if not given then it will everything."`
	Offset int `name:"offset" short:"o" help:"Skip first N keys."`
}

func (lkc *ListKeyCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	var keys []string
	var err error

	if lkc.Limit == 0 && lkc.Offset == 0 {
		err = _db_.RunInTx(ctx, db, func(txQuerier base.Querier) error {
			count, err := txQuerier.TotalKeys(ctx)
			if err != nil {
				return fmt.Errorf("failed to calculate total Keys: %w", err)
			}
			keys, err = txQuerier.ListKeys(ctx, base.ListKeysParams{Limit: count, Offset: 0})
			if err != nil {
				return fmt.Errorf("failed to list Keys: %w", err)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("transaction failed, data rolled back: %w", err)
		}
	} else {
		keys, err = query.ListKeys(ctx, base.ListKeysParams{Limit: int64(lkc.Limit), Offset: int64(lkc.Offset)})
		if err != nil {
			return fmt.Errorf("failed to list Keys: %w", err)
		}
	}

	fmt.Printf("Keys:\n")
	for _, key := range keys {
		fmt.Printf("    \u2022 %s\n", key)
	}

	return nil
}
