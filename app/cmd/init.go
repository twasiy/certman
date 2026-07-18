package cmd

import (
	_ "embed"
	"fmt"
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
	if err := _db_.InitializeDB(appDataPath); err != nil {
		return fmt.Errorf("Initialization failed: %w", err)
	}

	err = utils.InitMasterKey()
	if err != nil {
		return err
	}

	return nil
}
