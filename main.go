package main

import (
	"certman/app/cmd"
	"certman/app/utils"
	_db_ "certman/db"
	"certman/db/base"
	"context"
	"log"
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"
)

// this is implemented later
// Inspect cmd.InspectCmd `cmd:"" help:"Inspects Certificates and Key pairs. Prints raw information of Certificates or Keys."`

type CLI struct {
	Init cmd.InitCmd `cmd:"" help:"Initializes the Application and sets up the Database."`

	Gen    cmd.GenCmd    `cmd:"" help:"Gen Generates and Signs CA, Itermediate CA and Leaf Certificates and stores them in Database."`
	Read   cmd.ReadCmd   `cmd:"" help:"Read Reads Certificates or Keys using their identifiers."`
	Verify cmd.VerifyCmd `cmd:"" help:"Verifies Certificates and Key pairs."`
	List   cmd.ListCmd   `cmd:"" help:"List lists Certificates and Keys with or without pagination"`
	Export cmd.ExportCmd `cmd:"" help:"Exports Certificates and Public/Private keys in different formats. Supports (pem,der)"`
}

func (cli *CLI) AfterApply(ctx *kong.Context) error {
	currentCmd := ctx.Selected().Name

	if currentCmd == "init" {
		return nil
	}

	_, err := utils.GetMasterKey()
	if err != nil {
		return err
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

	if err := _db_.InitializeDB(appDataPath); err != nil {
		log.Fatalf("Initialization failed: %v", err)
	}

	sqlConn, err := _db_.GetConnection(dbPath)
	if err != nil {
		log.Fatalf("Database connection error: %v", err)
	}
	defer sqlConn.Close()

	ctx := context.Background()
	query := base.New(sqlConn)

	Kongctx := kong.Parse(&cli,
		kong.Name("certman"),
		kong.Description("A Certificate Management Toolkit"),
		kong.BindTo(ctx, (*context.Context)(nil)),
		kong.Bind(sqlConn),
		kong.BindTo(query, (*base.Querier)(nil)),
	)

	if err := Kongctx.Run(); err != nil {
		log.Fatal(err)
	}
}
