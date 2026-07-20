package gen

import (
	"context"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strconv"

	"certman/app/domain"
	"certman/app/utils"
	"certman/db/base"

	_db_ "certman/db"
)

type LeafCmd struct {
	CommonName         string   `name:"cn" required:"" help:"Common Name of the Certificate."`
	Country            []string `name:"country" short:"c" help:"Country names of the Certificate."`
	Organization       []string `name:"org" short:"o" help:"Organization names of the Certificate."`
	OrganizationalUnit []string `name:"ou" help:"OrganizationalUnit names of the Certificate."`
	Locality           []string `name:"locality" short:"l" help:"Locality names of the Certificate."`
	Province           []string `name:"st" help:"Province names of the Certificate."`
	StreetAddress      []string `name:"addr" help:"StreetAddress names of the Certificate."`
	PostalCode         []string `name:"zip" help:"PostalCode of the Certificate."`
	KeyType            string   `name:"algo" required:"" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ecdsa-256" help:"Key algorithm used to create the keys and sign the Certificate."`
	TTL                string   `name:"ttl" short:"t" required:"" help:"Time-To-Live of the certificate (e.g., 1000h, 30d, 10y)." default:"8760h"`
	DNSNames           []string `name:"dns" help:"DNSNames of the Certificate."`
	EmailAddresses     []string `name:"email" help:"EmailAddresses of the Certificate."`
	IPAddresses        []string `name:"ip" help:"IPAddresses of the Certificate."`
	URIs               []string `name:"uri" help:"URIs of the Certificate."`
	KeyUsages          []string `name:"ku" enum:"digital-signature,content-commitment,key-encipherment,data-encipherment,key-agreement,cert-sign,crl-sign,encipher-only,decipher-only" help:"Custom key usages (comma-separated or multiple flags)."`
	ExtKeyUsages       []string `name:"eku" enum:"any,server-auth,client-auth,code-signing,email-protection,time-stamping,ocsp-signing" help:"Custom extended key usages (comma-separated or multiple flags)."`

	ISerialNumber string `name:"isn" xor:"issuer" help:"Serial Number of the Issuer Certificate."`
	ICommonName   string `name:"icn" xor:"issuer" help:"Common Name of the Issuer Certificate."`
}

func (lc *LeafCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	hours, err := utils.ParseTTLToHours(lc.TTL)
	if err != nil {
		return fmt.Errorf("invalid entry for --ttl/-t: %v", err)
	}
	lc.TTL = strconv.Itoa(hours)

	issuerDBCert, err := lc.fetchIssuerCertificate(ctx, query)
	if err != nil {
		return err
	}
	issuerCert, err := utils.ParseCertificate([]byte(issuerDBCert.CertificatePem))
	if err != nil {
		return err
	}

	issuerKeys, err := query.GetKeyByName(ctx, issuerDBCert.KeyName)
	if err != nil {
		return fmt.Errorf("failed to get key: %w", err)
	}

	issuerPrivateKey, _, err := utils.ParseKeys([]byte(issuerKeys.PrivateKeyPem), []byte(issuerKeys.PublicKeyPem))
	if err != nil {
		return err
	}

	keyPair, err := domain.GetKey(domain.KeyType(lc.KeyType))
	if err != nil {
		return fmt.Errorf("unsupported key type: %s", lc.KeyType)
	}

	issuer := domain.Certificate{
		Cert: issuerCert,
		Keys: &domain.KeyPair{
			PrivateKey: issuerPrivateKey,
		},
	}

	usages := &domain.KeyUsageConfig{
		KeyUsages:    utils.ParseKeyUsages(lc.KeyUsages),
		ExtKeyUsages: utils.ParseExtKeyUsages(lc.ExtKeyUsages),
	}

	ttl, err := strconv.Atoi(lc.TTL)
	if err != nil {
		return err
	}
	leafCert, err := domain.GetLeaf(pkix.Name{
		Country:            lc.Country,
		Organization:       lc.Organization,
		OrganizationalUnit: lc.OrganizationalUnit,
		Locality:           lc.Locality,
		Province:           lc.Province,
		StreetAddress:      lc.StreetAddress,
		PostalCode:         lc.PostalCode,
		CommonName:         lc.CommonName,
	}, domain.SANs{
		DNSNames:       lc.DNSNames,
		EmailAddresses: lc.EmailAddresses,
		IPAddresses:    utils.ToNetIPs(lc.IPAddresses),
		URIs:           utils.ToURLs(lc.URIs),
	}, ttl, keyPair, &issuer, usages)
	if err != nil {
		return fmt.Errorf("cannot generate Leaf Certificate: %w", err)
	}

	// ----------------------------- WRITING TO THE DATABASE -------------------------------------

	privBlobPem, pubPem, err := utils.ReturnPrivPubPem(keyPair.PrivateKey, keyPair.PublicKey)
	if err != nil {
		return err
	}

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCert.Raw,
	})

	skidHex := hex.EncodeToString(leafCert.SubjectKeyId)
	akidHex := hex.EncodeToString(leafCert.AuthorityKeyId)

	err = _db_.RunInTx(ctx, db, func(txQuerier base.Querier) error {
		key, err := txQuerier.CreateKeyPair(ctx, base.CreateKeyPairParams{
			Name:          leafCert.Subject.CommonName,
			Algorithm:     lc.KeyType,
			PrivateKeyPem: privBlobPem,
			PublicKeyPem:  pubPem,
		})
		if err != nil {
			return fmt.Errorf("failed to create Key Pair in the database: %w", err)
		}

		_, err = txQuerier.CreateCertificate(ctx, base.CreateCertificateParams{
			SerialNumber:       fmt.Sprintf("%x", leafCert.SerialNumber),
			CommonName:         leafCert.Subject.CommonName,
			Type:               "LEAF",
			KeyName:            key.Name,
			IssuerSerialNumber: sql.NullString{String: fmt.Sprintf("%x", issuer.Cert.SerialNumber), Valid: false},
			Skid:               skidHex,
			Akid:               akidHex,
			NotBefore:          leafCert.NotBefore,
			NotAfter:           leafCert.NotAfter,
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

func (lc *LeafCmd) fetchIssuerCertificate(ctx context.Context, query base.Querier) (*base.Certificate, error) {
	if lc.ISerialNumber != "" && lc.ICommonName == "" {
		dbCert, err := query.GetCertificateBySN(ctx, lc.ISerialNumber)
		if err != nil {
			return nil, fmt.Errorf("failed to get Certificate: %w", err)
		}
		return &dbCert, nil
	} else if lc.ISerialNumber == "" && lc.ICommonName != "" {
		dbCert, err := query.GetCertificateByCN(ctx, lc.ICommonName)
		if err != nil {
			return nil, fmt.Errorf("failed to get Certificate: %w", err)
		}
		return &dbCert, nil
	} else {
		return nil, errors.New("exactly one flag (--sn or --cn) must be provided")
	}
}
