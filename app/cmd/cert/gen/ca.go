package gen

import (
	"certman/app/domain"
	"certman/app/utils"
	_db_ "certman/db"
	"certman/db/base"
	"context"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"strconv"
)

type CACmd struct {
	CommonName         string   `name:"cn" required:"" help:"Common Name of the Certificate."`
	Country            []string `name:"country" short:"c" help:"Country names of the Certificate."`
	Organization       []string `name:"org" short:"o" help:"Organization names of the Certificate."`
	OrganizationalUnit []string `name:"ou" help:"OrganizationalUnit names of the Certificate."`
	Locality           []string `name:"locality" short:"l" help:"Locality names of the Certificate."`
	Province           []string `name:"st" help:"Province names of the Certificate."`
	StreetAddress      []string `name:"addr" help:"StreetAddress names of the Certificate."`
	PostalCode         []string `name:"zip" help:"PostalCode of the Certificate."`
	KeyType            string   `name:"algo" required:"" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ed25519" help:"Key algorithm used to sign the Certificate."`
	TTL                string   `name:"ttl" required:"" short:"t" help:"Time-To-Live of the certificate (e.g., 1000h, 30d, 10y)." default:"86400h"`
	KeyUsages          []string `name:"ku" enum:"digital-signature,content-commitment,key-encipherment,data-encipherment,key-agreement,cert-sign,crl-sign,encipher-only,decipher-only" help:"Custom key usages (comma-separated or multiple flags)."`
}

func (cc *CACmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	hours, err := utils.ParseTTLToHours(cc.TTL)
	if err != nil {
		return fmt.Errorf("invalid entry for --ttl/-t: %v", err)
	}
	cc.TTL = strconv.Itoa(hours)

	keyPair, err := domain.GetKey(domain.KeyType(cc.KeyType))
	if err != nil {
		return fmt.Errorf("unsupported key type: %s", cc.KeyType)
	}

	usages := &domain.KeyUsageConfig{
		KeyUsages: utils.ParseKeyUsages(cc.KeyUsages),
	}

	ttl, err := strconv.Atoi(cc.TTL)
	if err != nil {
		return err
	}
	caCert, err := domain.GetCA(pkix.Name{
		Country:            cc.Country,
		Organization:       cc.Organization,
		OrganizationalUnit: cc.OrganizationalUnit,
		Locality:           cc.Locality,
		Province:           cc.Province,
		StreetAddress:      cc.StreetAddress,
		PostalCode:         cc.PostalCode,
		CommonName:         cc.CommonName,
	}, ttl, keyPair, usages)
	if err != nil {
		return fmt.Errorf("failed to generate CA Certificate: %w", err)
	}

	// ------------------------- WRITING TO THE DATABASE ------------------------------

	privBlobPem, pubPem, err := utils.ReturnPrivPubPem(keyPair.PrivateKey, keyPair.PublicKey)
	if err != nil {
		return err
	}

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})

	var skidHex, akidHex string
	if len(caCert.SubjectKeyId) > 0 {
		skidHex = hex.EncodeToString(caCert.SubjectKeyId)
	}
	if len(caCert.AuthorityKeyId) > 0 {
		akidHex = hex.EncodeToString(caCert.AuthorityKeyId)
	} else {
		// Fallback for self-signed root anchors
		akidHex = skidHex
	}

	err = _db_.RunInTx(ctx, db, func(txQuerier base.Querier) error {
		key, err := txQuerier.CreateKeyPair(ctx, base.CreateKeyPairParams{
			Name:          caCert.Subject.CommonName,
			Algorithm:     cc.KeyType,
			PrivateKeyPem: privBlobPem,
			PublicKeyPem:  pubPem,
		})
		if err != nil {
			return fmt.Errorf("failed to create Key Pair in the database: %w", err)
		}

		_, err = txQuerier.CreateCertificate(ctx, base.CreateCertificateParams{
			SerialNumber:       fmt.Sprintf("%x", caCert.SerialNumber),
			CommonName:         caCert.Subject.CommonName,
			Type:               "CA",
			KeyName:            key.Name,
			IssuerSerialNumber: sql.NullString{String: "", Valid: false},
			Skid:               skidHex,
			Akid:               akidHex,
			NotBefore:          caCert.NotBefore,
			NotAfter:           caCert.NotAfter,
			CertificatePem:     string(certPem),
		})
		if err != nil {
			return fmt.Errorf("failed to create Certificate in the database: %w", err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("transaction failed, data rolled back: %w", err)
	}

	log.Println("Success: successfully Created Certificate.")

	return nil
}
