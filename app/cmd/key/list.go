package key

import (
	_db_ "certman/db"
	"certman/db/base"
	"context"
	"database/sql"
	"fmt"
	"os"
	"text/tabwriter"
)

type ListCmd struct {
	Limit  int `name:"limit" short:"l" help:"Limit specifies how many keys to show. if not given then it will everything."`
	Offset int `name:"offset" short:"o" help:"Skip first N keys."`
}

func (lc *ListCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	var keys []base.ListKeysRow
	var err error

	if lc.Limit == 0 && lc.Offset == 0 {
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
		keys, err = query.ListKeys(ctx, base.ListKeysParams{Limit: int64(lc.Limit), Offset: int64(lc.Offset)})
		if err != nil {
			return fmt.Errorf("failed to list Keys: %w", err)
		}
	}

	if len(keys) == 0 {
		fmt.Println("No keys found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
	fmt.Fprintln(w, "KEY NAME\tALGORITHM\tCREATED AT")
	fmt.Fprintln(w, "--------\t---------\t----------")

	for _, k := range keys {
		createdAtStr := "N/A"

		if k.CreatedAt.Valid {
			createdAtStr = k.CreatedAt.Time.Format("2006-01-02 15:04:05")
		}

		fmt.Fprintf(w, "%s\t%s\t%s\n",
			k.Name,
			k.Algorithm,
			createdAtStr,
		)
	}

	return w.Flush()
}
