package db

import (
	"certman/db/base"
	"context"
	"database/sql"
	"fmt"
)

// RunInTx wraps operations inside an atomic SQLite transaction
func RunInTx(ctx context.Context, db *sql.DB, fn func(txQuerier base.Querier) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	txQueries := base.New(tx)

	err = fn(txQueries)
	if err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("tx error: %v, rollback failed: %v", err, rbErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
