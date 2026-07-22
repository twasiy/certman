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
package cmd

import (
	"certman/app/utils"
	_db_ "certman/db"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

type InitCmd struct{}

func (ic *InitCmd) Run() error {
	homDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to find user home directory: %w", err)
	}

	appDataPath := filepath.Join(homDir, ".certman")

	dbPath := filepath.Join(appDataPath, "certman.db")
	if _, err := os.Stat(dbPath); err == nil {
		_, keyErr := utils.GetMasterKey()
		if keyErr == nil {
			return fmt.Errorf("application is already initialized. Use 'certman' commands directly")
		}
		fmt.Println("Database exists but master key not found. Recreating master key...")
		return utils.InitMasterKey()
	}

	fmt.Printf("Initializing database at: %s\n", appDataPath)
	if err := _db_.InitializeDB(appDataPath); err != nil {
		return fmt.Errorf("Initialization failed: %w", err)
	}

	err = utils.InitMasterKey()
	if err != nil {
		if err.Error() == "Application is already initialized with a master key" {
			fmt.Println("Master key already exists")
			return nil
		}
		return err
	}

	fmt.Println("Application initialized successfully!")
	return nil
}
