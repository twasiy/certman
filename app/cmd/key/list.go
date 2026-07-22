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
package key

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"pkit/db/base"
	"text/tabwriter"
)

type ListCmd struct {
	Limit  int `name:"limit" short:"l" help:"Maximum number of key pairs to display."`
	Offset int `name:"offset" short:"o" help:"Number of initial rows to skip for pagination."`
}

func (lc *ListCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
	fmt.Fprintln(w, "KEY NAME\tALGORITHM\tCREATED AT")
	fmt.Fprintln(w, "--------\t---------\t----------")

	if lc.Limit == 0 && lc.Offset == 0 {
		keys, err := query.ListAllKeys(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch keys from DB: %w", err)
		}

		if len(keys) == 0 {
			fmt.Println("No keys found.")
			return nil
		}

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
	} else {
		keys, err := query.ListKeys(ctx, base.ListKeysParams{
			Limit:  int64(lc.Limit),
			Offset: int64(lc.Offset),
		})
		if err != nil {
			return fmt.Errorf("failed to fetch keys from DB: %w", err)
		}

		if len(keys) == 0 {
			fmt.Println("No keys found.")
			return nil
		}

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
}
