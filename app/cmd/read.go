package cmd

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
)

type ReadCmd struct{}

type ReadCertCmd struct {
	SerialNumber string `name:"sn" help:"Serial Number of the Certificate. Either one can be selected."`
	CommonName   string `name:"cn" help:"Common Name of the Certificate. Either one can be selected"`
}

func (rcc *ReadCertCmd) Run(ctx context.Context, query base.Querier) error {
	var cert base.Certificate
	var err error

	if rcc.SerialNumber != "" && rcc.CommonName == "" {
		cert, err = query.GetCertBySN(ctx, rcc.SerialNumber)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
	} else if rcc.SerialNumber == "" && rcc.CommonName != "" {
		cert, err = query.GetCertByCN(ctx, rcc.CommonName)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
	} else {
		return errors.New("One flag can be selected at a time")
	}

	fmt.Printf("\u2022 Serial Number: %s\n", cert.SerialNumber)
	fmt.Printf("\u2022 Common Name: %s\n", cert.CommonName)
	fmt.Printf("\u2022 Cert Type: %s\n", cert.Type)
	fmt.Printf("\n%s\n", cert.CertificatePem)

	return nil
}

type ReadKeyCmd struct {
	Name string `name:"key-name" aliases:"key" required:"" help:"Name of the Key Pair."`
}

func (rkc *ReadKeyCmd) Run(ctx context.Context, query base.Querier) error {
	key, err := query.GetKeyByName(ctx, rkc.Name)
	if err != nil {
		return fmt.Errorf("failed to get Key: %w", err)
	}

	fmt.Printf("\u2022 Name: %s\n", key.Name)
	fmt.Printf("\u2022 Algorithm: %s\n", key.Algorithm)

	masterKey, err := utils.GetMasterKey()
	if err != nil {
		return fmt.Errorf("failed to get master key from your OS keyring: %w", err)
	}
	privKey, _ := pem.Decode([]byte(key.PrivateKeyPem))
	if privKey == nil {
		return errors.New("failed to decode private key")
	}
	decryptedPrivateKey, err := utils.Decrypt(privKey.Bytes, masterKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt private key: %w", err)
	}

	privateKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: decryptedPrivateKey,
	})
	if privateKeyPem == nil {
		return errors.New("could not encode private key")
	}

	fmt.Printf("\n%s\n", string(privateKeyPem))
	fmt.Printf("\n%s\n", string(key.PublicKeyPem))

	return nil
}
