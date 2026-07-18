package cmd

import (
	"context"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"log"
	"strconv"
	"strings"

	"certman/app/domain"
	"certman/app/utils"
	"certman/db/base"

	"charm.land/huh/v2"
)

type CACmd struct {
	CommonName         string   `name:"common-name" aliases:"cn" help:"Common Name of the Certificate."`
	Country            []string `name:"country" aliases:"c" help:"Country names of the Certificate."`
	Organization       []string `name:"org" aliases:"o" help:"Organization names of the Certificate."`
	OrganizationalUnit []string `name:"org-unit" aliases:"ou" help:"OrganizationalUnit names of the Certificate."`
	Locality           []string `name:"locality" aliases:"l" help:"Locality names of the Certificate."`
	Province           []string `name:"province" aliases:"st" help:"Province names of the Certificate."`
	StreetAddress      []string `name:"street-addrs" aliases:"addr" help:"StreetAddress names of the Certificate"`
	PostalCode         []string `name:"postal-code" aliases:"zip" help:"PostalCode of the Certificate."`
	KeyType            string   `name:"key-type" aliases:"algo" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ed25519" help:"key-type specifies the Key will be used to sign the Certificate."`
	TTL                string   `name:"ttl" short:"t" help:"Time-To-Live of the certificate (e.g., 1000h, 30d, 10y)." default:"86400h"`
	IT                 bool     `name:"it" short:"i" help:"Bypass the flags and provide input via interactive prompt"`

	KeyUsages []string `name:"key-usage" aliases:"ku" help:"Custom key usages (comma-separated or multiple flags). e.g: cert-sign, crl-sign"`
}

func CAPrompt(initial *CACmd) (*CACmd, error) {
	var (
		cn         = initial.CommonName
		countries  = strings.Join(initial.Country, ", ")
		orgs       = strings.Join(initial.Organization, ", ")
		units      = strings.Join(initial.OrganizationalUnit, ", ")
		localities = strings.Join(initial.Locality, ", ")
		provinces  = strings.Join(initial.Province, ", ")
		streets    = strings.Join(initial.StreetAddress, ", ")
		posts      = strings.Join(initial.PostalCode, ", ")
		keyType    = initial.KeyType
		ttlStr     string

		keyUsages = initial.KeyUsages
	)

	if len(keyUsages) == 0 {
		keyUsages = []string{"cert-sign", "crl-sign"}
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
				Description("Choose cryptographic actions this CA is permitted to perform").
				Options(
					huh.NewOption("Certificate Signing (Default)", "cert-sign"),
					huh.NewOption("CRL Signing (Default)", "crl-sign"),
					huh.NewOption("Digital Signature", "digital-signature"),
					huh.NewOption("Content Commitment", "content-commitment"),
					huh.NewOption("Key Encipherment", "key-encipherment"),
					huh.NewOption("Data Encipherment", "data-encipherment"),
					huh.NewOption("Key Agreement", "key-agreement"),
				).Value(&keyUsages),
		),
		huh.NewGroup(
			huh.NewInput().Title("Countries (comma separated)").Value(&countries),
			huh.NewInput().Title("Organizations (comma separated)").Value(&orgs),
			huh.NewInput().Title("Organizational Units (comma separated)").Value(&units),
			huh.NewInput().Title("Localities (comma separated)").Value(&localities),
			huh.NewInput().Title("Provinces (comma separated)").Value(&provinces),
			huh.NewInput().Title("Street Addresses (comma separated)").Value(&streets),
			huh.NewInput().Title("Postal Codes (comma separated)").Value(&posts),
		),
	)

	if err := form.Run(); err != nil {
		return nil, err
	}

	parsedTTL, err := utils.ParseTTLToHours(ttlStr)
	if err != nil {
		return nil, err
	}
	return &CACmd{
		CommonName:         strings.TrimSpace(cn),
		Country:            utils.SplitCSV(countries),
		Organization:       utils.SplitCSV(orgs),
		OrganizationalUnit: utils.SplitCSV(units),
		Locality:           utils.SplitCSV(localities),
		Province:           utils.SplitCSV(provinces),
		StreetAddress:      utils.SplitCSV(streets),
		PostalCode:         utils.SplitCSV(posts),
		KeyType:            keyType,
		TTL:                strconv.Itoa(parsedTTL),
		IT:                 true,
		KeyUsages:          keyUsages,
	}, nil
}

func (cc *CACmd) Run(ctx context.Context, query base.Querier) error {
	finalConfig := cc
	if cc.IT {
		promptResult, err := CAPrompt(cc)
		if err != nil {
			return fmt.Errorf("prompt cancelled: %w", err)
		}
		finalConfig = promptResult
	} else {
		if finalConfig.CommonName == "" {
			return fmt.Errorf("missing required flag: --common-name/--cn")
		}
		if finalConfig.KeyType == "" {
			return fmt.Errorf("missing required flag: --key-type/--algo")
		}
		hours, err := utils.ParseTTLToHours(cc.TTL)
		if err != nil {
			return fmt.Errorf("invalid entry for --ttl/-t: %v", err)
		}
		finalConfig.TTL = strconv.Itoa(hours)
	}

	keyPair, err := domain.GetKey(domain.KeyType(finalConfig.KeyType))
	if err != nil {
		return fmt.Errorf("unsupported key type: %s", finalConfig.KeyType)
	}

	usages := &domain.KeyUsageConfig{
		KeyUsages: utils.ParseKeyUsages(finalConfig.KeyUsages),
	}

	ttl, err := strconv.Atoi(finalConfig.TTL)
	if err != nil {
		return err
	}
	caCert, err := domain.GetCA(pkix.Name{
		Country:            finalConfig.Country,
		Organization:       finalConfig.Organization,
		OrganizationalUnit: finalConfig.OrganizationalUnit,
		Locality:           finalConfig.Locality,
		Province:           finalConfig.Province,
		StreetAddress:      finalConfig.StreetAddress,
		PostalCode:         finalConfig.PostalCode,
		CommonName:         finalConfig.CommonName,
	}, ttl, keyPair, usages)
	if err != nil {
		return fmt.Errorf("failed to generate CA Certificate: %w", err)
	}

	// ------------------------- WRITING TO THE DATABASE ------------------------------

	privBlobPem, pubPem, err := ReturnPrivPubPem(keyPair.PrivateKey, keyPair.PublicKey)
	if err != nil {
		return err
	}

	key, err := query.CreateKeyPair(ctx, base.CreateKeyPairParams{
		Name:          caCert.Subject.CommonName,
		Algorithm:     finalConfig.KeyType,
		PrivateKeyPem: privBlobPem,
		PublicKeyPem:  pubPem,
	})
	if err != nil {
		return fmt.Errorf("failed to create Key Pair in the database: %w", err)
	}

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})

	cert, err := query.CreateCertificate(ctx, base.CreateCertificateParams{
		SerialNumber:                  caCert.SerialNumber.String(),
		CommonName:                    caCert.Subject.CommonName,
		Type:                          "CA",
		KeyName:                       key.Name,
		IssuerCertificateSerialNumber: sql.NullString{String: "", Valid: false},
		NotBefore:                     caCert.NotBefore,
		NotAfter:                      caCert.NotAfter,
		CertificatePem:                string(certPem),
	})
	if err != nil {
		return fmt.Errorf("failed to create Certificate in the database: %w", err)
	}

	log.Println("Success: successfully Created Certificate and it's Key Pair:")
	fmt.Printf("        \u2022 Certificate Serial Number: %s\n", cert.SerialNumber)
	fmt.Printf("        \u2022 Certificate Common Name: %s\n", cert.CommonName)

	return nil
}
