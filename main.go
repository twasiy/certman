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
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"pkit/app/cmd"
	"pkit/app/cmd/cert"
	"pkit/app/cmd/crl"
	"pkit/app/cmd/csr"
	"pkit/app/cmd/key"
	"pkit/app/utils"
	_db_ "pkit/db"
	"pkit/db/base"

	"github.com/alecthomas/kong"
)

type CLI struct {
	Init cmd.InitCmd `cmd:"" help:"Initialize the application, environment configuration, and database storage."`

	Cert cert.CertCmd `cmd:"" help:"Manage X.509 certificates (generate, inspect, verify, revoke, rotate, export)."`
	Key  key.KeyCmd   `cmd:"" help:"Manage cryptographic key pairs (list, inspect, verify integrity, export)."`
	CSR  csr.CSRCmd   `cmd:"" help:"Manage Certificate Signing Requests (generate, inspect, sign, export)."`
	CRL  crl.CrlCmd   `cmd:"" help:"Manage Certificate Revocation Lists (generate, inspect, verify, export)."`
}

func (cli *CLI) AfterApply(ctx *kong.Context) error {
	currentCmd := ctx.Selected().Name

	if currentCmd == "init" {
		return nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not get user home directory: %w", err)
	}

	appDataPath := filepath.Join(home, ".certman")
	dbPath := filepath.Join(appDataPath, "certman.db")

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return fmt.Errorf("application not initialized. Please run 'pkit init' first")
	}

	_, err = utils.GetMasterKey()
	if err != nil {
		return fmt.Errorf("application not properly initialized. Please run 'pkit init' first")
	}

	return nil
}

func main() {
	cli := CLI{}

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("could not get user home directory: %v", err)
	}

	appDataPath := filepath.Join(home, ".pkit")
	dbPath := filepath.Join(appDataPath, "pkit.db")

	var connection *sql.DB
	var query base.Querier

	args := os.Args[1:]
	isInitCommand := len(args) > 0 && args[0] == "init"

	if !isInitCommand {
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			log.Fatalf("Application not initialized. Please run 'pkit init' first")
		}

		connection, err = _db_.GetConnection(dbPath)
		if err != nil {
			log.Fatalf("Database connection error: %v", err)
		}
		defer connection.Close()

		if err := connection.Ping(); err != nil {
			log.Fatalf("Cannot connect to database: %v", err)
		}

		query = base.New(connection)
	}

	ctx := context.Background()

	Kongctx := kong.Parse(&cli,
		kong.Name("pkit"),
		kong.Description("A complete internal PKI lifecycle management toolkit."),
		kong.BindTo(ctx, (*context.Context)(nil)),
	)

	if connection != nil && query != nil {
		Kongctx.Bind(connection)
		Kongctx.BindTo(query, (*base.Querier)(nil))
	}

	if err := Kongctx.Run(); err != nil {
		log.Fatal(err)
	}
}
