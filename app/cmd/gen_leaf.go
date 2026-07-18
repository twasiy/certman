package cmd

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"certman/app/domain"
	"certman/app/utils"
	"certman/db/base"

	_db_ "certman/db"

	"charm.land/huh/v2"
)

type LeafCmd struct {
	CommonName         string   `name:"cn" help:"Common Name of the Certificate."`
	Country            []string `name:"country" short:"c" help:"Country names of the Certificate."`
	Organization       []string `name:"org" short:"o" help:"Organization names of the Certificate."`
	OrganizationalUnit []string `name:"ou" help:"OrganizationalUnit names of the Certificate."`
	Locality           []string `name:"locality" short:"l" help:"Locality names of the Certificate."`
	Province           []string `name:"st" help:"Province names of the Certificate."`
	StreetAddress      []string `name:"addr" help:"StreetAddress names of the Certificate"`
	PostalCode         []string `name:"zip" help:"PostalCode of the Certificate."`
	KeyType            string   `name:"algo" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ecdsa-256" help:"key-type specifies the Key algorithm will be used to create the keys and sign the Certificate."`
	TTL                string   `name:"ttl" short:"t" help:"Time-To-Live of the certificate (e.g., 1000h, 30d, 10y)." default:"8760h"`
	DNSNames           []string `name:"dns" help:"DNSNames of the Certificate."`
	EmailAddresses     []string `name:"email" help:"EmailAddresses of the Certificate"`
	IPAddresses        []string `name:"ip" help:"IPAddresses of the Certificate."`
	URIs               []string `name:"uri" help:"URIs of the Certificate"`
	IT                 bool     `name:"it" short:"i" help:"Bypass the flags and provide input via interactive prompt"`

	ISerialNumber string `name:"isn" help:"Serial Number of the Issuer Certificate. Either one can be selected."`
	ICommonName   string `name:"icn" help:"Common Name of the Issuer Certificate. Either one can be selected"`

	KeyUsages    []string `name:"ku" help:"Custom key usages (comma-separated or multiple flags). e.g: digital-signature, key-encipherment"`
	ExtKeyUsages []string `name:"eku" help:"Custom extended key usages (comma-separated or multiple flags). e.g: server-auth, client-auth"`
}

func LeafPrompt(initial *LeafCmd) (*LeafCmd, error) {
	var (
		cn             = initial.CommonName
		countries      = strings.Join(initial.Country, ", ")
		orgs           = strings.Join(initial.Organization, ", ")
		units          = strings.Join(initial.OrganizationalUnit, ", ")
		localities     = strings.Join(initial.Locality, ", ")
		provinces      = strings.Join(initial.Province, ", ")
		streets        = strings.Join(initial.StreetAddress, ", ")
		posts          = strings.Join(initial.PostalCode, ", ")
		keyType        = initial.KeyType
		dnsNames       = strings.Join(initial.DNSNames, ", ")
		emailAddresses = strings.Join(initial.EmailAddresses, ", ")
		ipAddresses    = strings.Join(initial.IPAddresses, ", ")
		uris           = strings.Join(initial.URIs, ", ")
		ttlStr         string

		keyUsages    = initial.KeyUsages
		extKeyUsages = initial.ExtKeyUsages
	)

	if len(keyUsages) == 0 {
		keyUsages = []string{"digital-signature", "key-encipherment"}
	}
	if len(extKeyUsages) == 0 {
		extKeyUsages = []string{"server-auth", "client-auth"}
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Common Name").Value(&cn).Validate(func(s string) error {
				if strings.TrimSpace(s) == "" {
					return fmt.Errorf("common name cannot be left blank")
				}
				return nil
			}),
			huh.NewSelect[string]().
				Title("Key Type").
				Options(
					huh.NewOption("RSA 2048", "rsa-2048"),
					huh.NewOption("RSA 4096", "rsa-4096"),
					huh.NewOption("ECDSA 224", "ecdsa-224"),
					huh.NewOption("ECDSA 256", "ecdsa-256"),
					huh.NewOption("ECDSA 384", "ecdsa-384"),
					huh.NewOption("ECDSA 521", "ecdsa-521"),
					huh.NewOption("Ed25519", "ed25519"),
				).Value(&keyType),
			huh.NewInput().Title("TTL (Time To Live)").
				Description("Specify duration, e.g., 1000h (hours), 30d (days), 10y (years)").
				Value(&ttlStr).Validate(func(str string) error {
				_, err := utils.ParseTTLToHours(str)
				return err
			}),
			huh.NewMultiSelect[string]().
				Title("Allowed Key Usages").
				Description("Choose cryptographic actions this Leaf certificate is permitted to perform").
				Options(
					huh.NewOption("Digital Signature (Default)", "digital-signature"),
					huh.NewOption("Key Encipherment (Default)", "key-encipherment"),
					huh.NewOption("Content Commitment", "content-commitment"),
					huh.NewOption("Data Encipherment", "data-encipherment"),
					huh.NewOption("Key Agreement", "key-agreement"),
				).Value(&keyUsages),
			huh.NewMultiSelect[string]().
				Title("Extended Key Usages").
				Description("Define validation scopes for this Leaf certificate").
				Options(
					huh.NewOption("Server Authentication (Default)", "server-auth"),
					huh.NewOption("Client Authentication (Default)", "client-auth"),
					huh.NewOption("Code Signing", "code-signing"),
					huh.NewOption("Email Protection", "email-protection"),
					huh.NewOption("Time Stamping", "time-stamping"),
					huh.NewOption("OCSP Signing", "ocsp-signing"),
					huh.NewOption("Any Purpose", "any"),
				).Value(&extKeyUsages),
		),
		huh.NewGroup(
			huh.NewInput().Title("Countries (comma separated)").Value(&countries),
			huh.NewInput().Title("Organizations (comma separated)").Value(&orgs),
			huh.NewInput().Title("Organizational Units (comma separated)").Value(&units),
			huh.NewInput().Title("Localities (comma separated)").Value(&localities),
			huh.NewInput().Title("Provinces (comma separated)").Value(&provinces),
			huh.NewInput().Title("Street Addresses (comma separated)").Value(&streets),
			huh.NewInput().Title("Postal Codes (comma separated)").Value(&posts),
			huh.NewInput().Title("DNS Names (comma separated)").Value(&dnsNames),
			huh.NewInput().Title("Email Addresses (comma separated)").Value(&emailAddresses),
			huh.NewInput().Title("IP Addresses (comma separated)").Value(&ipAddresses),
			huh.NewInput().Title("URIs (comma separated)").Value(&uris),
		),
	)

	if err := form.Run(); err != nil {
		return nil, err
	}

	parsedTTL, err := utils.ParseTTLToHours(ttlStr)
	if err != nil {
		return nil, err
	}
	return &LeafCmd{
		CommonName:         strings.TrimSpace(cn),
		Country:            utils.SplitCSV(countries),
		Organization:       utils.SplitCSV(orgs),
		OrganizationalUnit: utils.SplitCSV(units),
		Locality:           utils.SplitCSV(localities),
		Province:           utils.SplitCSV(provinces),
		StreetAddress:      utils.SplitCSV(streets),
		PostalCode:         utils.SplitCSV(posts),
		DNSNames:           utils.SplitCSV(dnsNames),
		EmailAddresses:     utils.SplitCSV(emailAddresses),
		IPAddresses:        utils.SplitCSV(ipAddresses),
		URIs:               utils.SplitCSV(uris),
		KeyType:            keyType,
		TTL:                strconv.Itoa(parsedTTL),
		IT:                 true,
		KeyUsages:          keyUsages,
		ExtKeyUsages:       extKeyUsages,
	}, nil
}

func (lc *LeafCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	finalConfig := lc
	if lc.IT {
		promptResult, err := LeafPrompt(lc)
		if err != nil {
			return fmt.Errorf("prompt cancelled or failed: %w", err)
		}
		finalConfig = promptResult
	} else {
		if finalConfig.CommonName == "" {
			return fmt.Errorf("missing required flag: --common-name/--cn")
		}
		if finalConfig.KeyType == "" {
			return fmt.Errorf("missing required flag: --key-type/--algo")
		}
		hours, err := utils.ParseTTLToHours(lc.TTL)
		if err != nil {
			return fmt.Errorf("invalid entry for --ttl/-t: %v", err)
		}
		finalConfig.TTL = strconv.Itoa(hours)
	}

	var issuerCert *x509.Certificate
	var keyName string
	if lc.ISerialNumber != "" && lc.ICommonName == "" {
		dbCert, err := query.GetCertBySN(ctx, lc.ISerialNumber)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
		keyName = dbCert.KeyName
		issuerCert, err = ParseCertificate([]byte(dbCert.CertificatePem))
		if err != nil {
			return err
		}
	} else if lc.ISerialNumber == "" && lc.ICommonName != "" {
		dbCert, err := query.GetCertByCN(ctx, lc.ICommonName)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
		keyName = dbCert.KeyName
		issuerCert, err = ParseCertificate([]byte(dbCert.CertificatePem))
		if err != nil {
			return err
		}
	} else {
		return errors.New("exactly one flag (--isn or --icn) must be provided")
	}

	issuerKeys, err := query.GetKeyByName(ctx, keyName)
	if err != nil {
		return fmt.Errorf("failed to get key: %w", err)
	}

	issuerPrivateKey, _, err := ParseKeys([]byte(issuerKeys.PrivateKeyPem), []byte(issuerKeys.PublicKeyPem))
	if err != nil {
		return err
	}

	keyPair, err := domain.GetKey(domain.KeyType(finalConfig.KeyType))
	if err != nil {
		return fmt.Errorf("unsupported key type: %s", finalConfig.KeyType)
	}

	issuer := domain.Certificate{
		Cert: issuerCert,
		Keys: &domain.KeyPair{
			PrivateKey: issuerPrivateKey,
		},
	}

	usages := &domain.KeyUsageConfig{
		KeyUsages:    utils.ParseKeyUsages(finalConfig.KeyUsages),
		ExtKeyUsages: utils.ParseExtKeyUsages(finalConfig.ExtKeyUsages),
	}

	ttl, err := strconv.Atoi(finalConfig.TTL)
	if err != nil {
		return err
	}
	leafCert, err := domain.GetLeaf(pkix.Name{
		Country:            finalConfig.Country,
		Organization:       finalConfig.Organization,
		OrganizationalUnit: finalConfig.OrganizationalUnit,
		Locality:           finalConfig.Locality,
		Province:           finalConfig.Province,
		StreetAddress:      finalConfig.StreetAddress,
		PostalCode:         finalConfig.PostalCode,
		CommonName:         finalConfig.CommonName,
	}, domain.SANs{
		DNSNames:       finalConfig.DNSNames,
		EmailAddresses: finalConfig.EmailAddresses,
		IPAddresses:    utils.ToNetIPs(finalConfig.IPAddresses),
		URIs:           utils.ToURLs(finalConfig.URIs),
	}, ttl, keyPair, &issuer, usages)
	if err != nil {
		return fmt.Errorf("cannot generate Leaf Certificate: %w", err)
	}

	// ----------------------------- WRITING TO THE DATABASE -------------------------------------

	privBlobPem, pubPem, err := ReturnPrivPubPem(keyPair.PrivateKey, keyPair.PublicKey)
	if err != nil {
		return err
	}

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCert.Raw,
	})

	err = _db_.RunInTx(ctx, db, func(txQuerier base.Querier) error {
		key, err := txQuerier.CreateKeyPair(ctx, base.CreateKeyPairParams{
			Name:          leafCert.Subject.CommonName,
			Algorithm:     finalConfig.KeyType,
			PrivateKeyPem: privBlobPem,
			PublicKeyPem:  pubPem,
		})
		if err != nil {
			return fmt.Errorf("failed to create Key Pair in the database: %w", err)
		}

		_, err = txQuerier.CreateCertificate(ctx, base.CreateCertificateParams{
			SerialNumber:                  leafCert.SerialNumber.String(),
			CommonName:                    leafCert.Subject.CommonName,
			Type:                          "LEAF",
			KeyName:                       key.Name,
			IssuerCertificateSerialNumber: sql.NullString{String: issuer.Cert.SerialNumber.String(), Valid: false},
			NotBefore:                     leafCert.NotBefore,
			NotAfter:                      leafCert.NotAfter,
			CertificatePem:                string(certPem),
		})
		if err != nil {
			return fmt.Errorf("failed to create Certificate in the database: %w", err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("transaction failed, data rolled back: %w", err)
	}

	log.Println("Success: successfully Created Certificate and it's Key Pair:")

	return nil
}
