package cmd

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"certman/app/utils"
	_db_ "certman/db"

	_ "github.com/mattn/go-sqlite3"
)

type InitCmd struct{}

func (ic *InitCmd) Run() error {

	homDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not find user home directory: %w", err)
	}

	appDataPath := filepath.Join(homDir, ".certman")

	if err := InitializeDB(appDataPath); err != nil {
		return fmt.Errorf("Initialization failed: %w", err)
	}

	err = utils.InitMasterKey()
	if err != nil {
		return err
	}

	return nil
}

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

	_, err = db.Exec("PRAGMA foreign_keys = ON;")
	if err != nil {
		return fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	_, err = db.ExecContext(context.Background(), _db_.Schema)
	if err != nil {
		return fmt.Errorf("failed to execute schema initialization: %w", err)
	}

	log.Println("Success: Database structures successfully populated!")
	return nil
}
