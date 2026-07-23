package testutil

import (
	"database/sql"
	"fmt"
)

func GetInMemoryDB(dbName string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", dbName)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Verify connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db.SetMaxOpenConns(1) // Keeps single connection active to prevent early cleanup

	return db, nil
}
