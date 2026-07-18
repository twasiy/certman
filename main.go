package main

import (
	"certman/app/cmd"
	"certman/app/utils"
	"certman/db"
	"certman/db/base"
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kong"
)

type CLI struct {
	Init cmd.InitCmd `cmd:"" help:"Initializes the Application and sets up the Database."`

	Gen    cmd.GenCmd    `cmd:"" help:"Gen Generates and Signs CA, Itermediate CA and Leaf Certificates and stores them in Database."`
	Read   cmd.ReadCmd   `cmd:"" help:"Read Reads Certificates or Keys using their identifiers."`
	Verify cmd.VerifyCmd `cmd:"" help:"Verifies Certificates and Key pairs."`
	List   cmd.ListCmd   `cmd:"" help:"List lists Certificates and Keys with or without pagination"`
	// Inspect cmd.InspectCmd `cmd:"" help:"Inspects Certificates and Key pairs. Prints raw information of Certificates or Keys."`
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

	dbPath := filepath.Join(home, ".certman/certman.db")
	_, err = os.Stat(dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			err := cmd.InitializeDB(strings.TrimSuffix(dbPath, "/certman.db"))
			if err != nil {
				log.Fatal(err.Error())
			}
		}
		log.Fatalf("something occured while checking the file: %v", err)
	}

	sqlConn, err := db.GetConnection(dbPath)
	if err != nil {
		log.Fatalf("Database connection error: %v", err)
	}
	defer sqlConn.Close()

	ctx := context.Background()
	query := base.New(sqlConn)

	Kongctx := kong.Parse(&cli,
		kong.Name("certman"),
		kong.Description("A Certificate Management Toolkit"),
		kong.Bind(ctx, query),
	)

	err = Kongctx.Run()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
