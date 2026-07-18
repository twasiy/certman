package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// InitializeDB handles creating the folder, the file, and running the schema
func InitializeDB(dbDir string) error {
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	dbPath := filepath.Join(dbDir, "certman.db")
	fmt.Printf("Initializing database at: %s\n", dbPath)

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		return fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	if _, err := db.ExecContext(context.Background(), Schema); err != nil {
		return fmt.Errorf("failed to execute schema initialization: %w", err)
	}

	log.Println("Success: Database structures successfully populated!")
	return nil
}
