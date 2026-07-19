package main

import (
	"certman/app/cmd"
	"certman/app/cmd/cert"
	"certman/app/cmd/crl"
	"certman/app/cmd/key"
	"certman/app/utils"
	_db_ "certman/db"
	"certman/db/base"
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"
)

type CLI struct {
	Init cmd.InitCmd `cmd:"" help:"Initializes the Application and sets up the Database."`

	Certificate cert.CertificateCmd `cmd:"" help:"Certificate operations"`
	Key         key.KeyCmd          `cmd:"" help:"Key operations"`
	CRL         crl.CrlCmd          `cmd:"" help:"CRL operations"`
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
		return fmt.Errorf("application not initialized. Please run 'certman init' first")
	}

	_, err = utils.GetMasterKey()
	if err != nil {
		return fmt.Errorf("application not properly initialized. Please run 'certman init' first")
	}

	return nil
}

func main() {
	cli := CLI{}

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("could not get user home directory: %v", err)
	}

	appDataPath := filepath.Join(home, ".certman")
	dbPath := filepath.Join(appDataPath, "certman.db")

	var connection *sql.DB
	var query base.Querier

	args := os.Args[1:]
	isInitCommand := len(args) > 0 && args[0] == "init"

	if !isInitCommand {
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			log.Fatalf("Application not initialized. Please run 'certman init' first")
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
		kong.Name("certman"),
		kong.Description("A Certificate Management Toolkit"),
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
