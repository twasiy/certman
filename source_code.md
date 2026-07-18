# Code documentation for `certman`

*Generated from: `/home/tassok/CLI/certman`*

**Extensions included:** .go

---

## `app/cmd/export.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/export.go`
- **Size:** 4795 bytes

```go
package cmd

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type ExportCmd struct {
	Cert ExportCertCmd `cmd:"" help:"Exports Certificates in different formats (e.g.,pem, der)."`
	Key  ExportKeyCmd  `cmd:"" help:"Exports public/private key in different formats (e.g.,pem,der)."`
}

type ExportCertCmd struct {
	SerialNumber string `name:"sn" help:"Serial Number of the Certificate. Either one can be selected."`
	CommonName   string `name:"cn" help:"Common Name of the Certificate. Either one can be selected"`
	Path         string `name:"path" short:"p" type:"path" help:"Path to export the file. [file name must be omitted]"`
	Format       string `name:"format" short:"f" help:"Specific format to export (e.g.,pem,der)"`
}

func (ecc *ExportCertCmd) Run(ctx context.Context, query base.Querier) error {
	var cert base.Certificate
	var err error

	if ecc.SerialNumber != "" && ecc.CommonName == "" {
		cert, err = query.GetCertBySN(ctx, ecc.SerialNumber)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
	} else if ecc.SerialNumber == "" && ecc.CommonName != "" {
		cert, err = query.GetCertByCN(ctx, ecc.CommonName)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
	} else {
		return errors.New("exactly one flag (--sn or --cn) must be provided")
	}

	ext := ".pem"
	if ecc.Format == "der" {
		ext = ".der"
	}

	var filePath string
	baseName := cert.CommonName + ext
	if ecc.Path != "" {
		targetDir, err := utils.JoinHomeDir(ecc.Path)
		if err != nil {
			return err
		}
		filePath = filepath.Join(targetDir, baseName)
	} else {
		filePath = baseName
	}

	if ecc.Format == "pem" {
		err := os.WriteFile(filePath, []byte(cert.CertificatePem), 0o644)
		if err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
	} else {
		block, _ := pem.Decode([]byte(cert.CertificatePem))
		if block == nil {
			return errors.New("failed to decode PEM formatted Certificate")
		}
		err = os.WriteFile(filePath, block.Bytes, 0o644)
		if err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
	}

	return nil
}

type ExportKeyCmd struct {
	Name   string `name:"key-name" aliases:"key" required:"" help:"Name of the Key Pair."`
	Path   string `name:"path" short:"p" type:"path" help:"Path to export the file. [file name must be omitted]"`
	Format string `name:"format" short:"f" help:"Specific format to export (e.g.,pem,der)"`
	Blob   bool   `name:"blob" short:"b" help:"If selected private key will be exported as encrypted blob encoded into PEM."`
}

func (ekc *ExportKeyCmd) Run(ctx context.Context, query base.Querier) error {
	key, err := query.GetKeyByName(ctx, ekc.Name)
	if err != nil {
		return fmt.Errorf("failed to get key: %w", err)
	}

	ext := ".pem"
	if ekc.Format == "der" {
		ext = ".der"
	}

	var tempPath string
	if ekc.Path != "" {
		tempPath, err = utils.JoinHomeDir(ekc.Path)
		if err != nil {
			return err
		}
	}
	privKeyFilePath := filepath.Join(tempPath, utils.ToSnakeCase(key.Name)+"_private_key"+ext)
	pubKeyFilePath := filepath.Join(tempPath, utils.ToSnakeCase(key.Name)+"_public_key"+ext)

	if ekc.Format == "pem" {
		if !ekc.Blob {
			decryptedPrivKey, err := DecryptPrivKey([]byte(key.PrivateKeyPem))
			if err != nil {
				return err
			}
			privPemBytes := pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: decryptedPrivKey,
			})
			err = os.WriteFile(privKeyFilePath, privPemBytes, 0o600)
			if err != nil {
				return fmt.Errorf("failed to write private key: %w", err)
			}
		} else {
			err = os.WriteFile(privKeyFilePath, []byte(key.PrivateKeyPem), 0o600)
			if err != nil {
				return fmt.Errorf("failed to write private key: %w", err)
			}
		}

		err = os.WriteFile(pubKeyFilePath, []byte(key.PublicKeyPem), 0o644)
		if err != nil {
			return fmt.Errorf("failed to write public key: %w", err)
		}

	} else {

		if !ekc.Blob {
			decryptedPrivKey, err := DecryptPrivKey([]byte(key.PrivateKeyPem))
			if err != nil {
				return err
			}
			err = os.WriteFile(privKeyFilePath, decryptedPrivKey, 0o600)
			if err != nil {
				return fmt.Errorf("failed to write private key: %w", err)
			}
		} else {
			privBlock, _ := pem.Decode([]byte(key.PrivateKeyPem))
			if privBlock == nil {
				return errors.New("failed to decode private key")
			}
			err = os.WriteFile(privKeyFilePath, privBlock.Bytes, 0o600)
			if err != nil {
				return fmt.Errorf("failed to write private key: %w", err)
			}
		}

		pubBlock, _ := pem.Decode([]byte(key.PublicKeyPem))
		if pubBlock == nil {
			return errors.New("failed to decode public key")
		}
		err = os.WriteFile(pubKeyFilePath, pubBlock.Bytes, 0o644)
		if err != nil {
			return fmt.Errorf("failed to write public key: %w", err)
		}
	}

	return nil
}
```

---

## `app/cmd/gen.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/gen.go`
- **Size:** 228 bytes

```go
package cmd

type GenCmd struct {
	CA   CACmd      `cmd:"" help:"Generates CA Certificate."`
	ICA  InterCACmd `cmd:"" help:"Generates Intermediate CA Certificate."`
	Leaf LeafCmd    `cmd:"" help:"Generates Leaf Certificate."`
}
```

---

## `app/cmd/gen_ca.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/gen_ca.go`
- **Size:** 7935 bytes

```go
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

	database "certman/db"

	"charm.land/huh/v2"
)

type CACmd struct {
	CommonName         string   `name:"cn" help:"Common Name of the Certificate."`
	Country            []string `name:"country" short:"c" help:"Country names of the Certificate."`
	Organization       []string `name:"org" short:"o" help:"Organization names of the Certificate."`
	OrganizationalUnit []string `name:"ou" help:"OrganizationalUnit names of the Certificate."`
	Locality           []string `name:"locality" short:"l" help:"Locality names of the Certificate."`
	Province           []string `name:"st" help:"Province names of the Certificate."`
	StreetAddress      []string `name:"addr" help:"StreetAddress names of the Certificate"`
	PostalCode         []string `name:"zip" help:"PostalCode of the Certificate."`
	KeyType            string   `name:"algo" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ed25519" help:"key-type specifies the Key will be used to sign the Certificate."`
	TTL                string   `name:"ttl" short:"t" help:"Time-To-Live of the certificate (e.g., 1000h, 30d, 10y)." default:"86400h"`
	IT                 bool     `name:"it" short:"i" help:"Bypass the flags and provide input via interactive prompt"`

	KeyUsages []string `name:"ku" help:"Custom key usages (comma-separated or multiple flags). e.g: cert-sign, crl-sign"`
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

func (cc *CACmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	finalConfig := cc
	if cc.IT {
		promptResult, err := CAPrompt(cc)
		if err != nil {
			return fmt.Errorf("prompt cancelled or failed: %w", err)
		}
		finalConfig = promptResult
	} else {
		hours, err := utils.ParseTTLToHours(cc.TTL)
		if err != nil {
			return fmt.Errorf("invalid entry for --ttl/-t: %v", err)
		}
		finalConfig.TTL = strconv.Itoa(hours)

		if finalConfig.CommonName == "" {
			return fmt.Errorf("missing required flag: --common-name/--cn")
		}
		if finalConfig.KeyType == "" {
			return fmt.Errorf("missing required flag: --key-type/--algo")
		}
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

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})

	err = database.RunInTx(ctx, db, func(txQuerier base.Querier) error {
		key, err := query.CreateKeyPair(ctx, base.CreateKeyPairParams{
			Name:          caCert.Subject.CommonName,
			Algorithm:     finalConfig.KeyType,
			PrivateKeyPem: privBlobPem,
			PublicKeyPem:  pubPem,
		})
		if err != nil {
			return fmt.Errorf("failed to create Key Pair in the database: %w", err)
		}

		_, err = query.CreateCertificate(ctx, base.CreateCertificateParams{
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

		return nil
	})

	if err != nil {
		return fmt.Errorf("transaction failed, data rolled back: %w", err)
	}

	log.Println("Success: successfully Created Certificate and it's Key Pair.")

	return nil
}
```

---

## `app/cmd/gen_ica.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/gen_ica.go`
- **Size:** 11693 bytes

```go
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
	database "certman/db"
	"certman/db/base"

	"charm.land/huh/v2"
)

type InterCACmd struct {
	CommonName         string   `name:"cn" help:"Common Name of the Certificate."`
	Country            []string `name:"country" short:"c" help:"Country names of the Certificate."`
	Organization       []string `name:"org" short:"o" help:"Organization names of the Certificate."`
	OrganizationalUnit []string `name:"ou" help:"OrganizationalUnit names of the Certificate."`
	Locality           []string `name:"locality" short:"l" help:"Locality names of the Certificate."`
	Province           []string `name:"st" help:"Province names of the Certificate."`
	StreetAddress      []string `name:"addr" help:"StreetAddress names of the Certificate"`
	PostalCode         []string `name:"zip" help:"PostalCode of the Certificate."`
	KeyType            string   `name:"algo" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ecdsa-256" help:"key-type specifies the Key algorithm will be used to crear the keys and sign the Certificate."`
	TTL                string   `name:"ttl" short:"t" help:"Time-To-Live of the certificate (e.g., 1000h, 30d, 10y)." default:"17280h"`
	DNSNames           []string `name:"dns" help:"DNSNames of the Certificate."`
	EmailAddresses     []string `name:"email" help:"EmailAddresses of the Certificate"`
	IPAddresses        []string `name:"ip" help:"IPAddresses of the Certificate."`
	URIs               []string `name:"uri" help:"URIs of the Certificate"`
	IT                 bool     `name:"it" short:"i" help:"Bypass the flags and provide input via interactive prompt"`

	ISerialNumber string `name:"isn" help:"Serial Number of the Issuer Certificate. Either one can be selected."`
	ICommonName   string `name:"icn" help:"Common Name of the Issuer Certificate. Either one can be selected"`

	KeyUsages    []string `name:"ku" help:"Custom key usages (comma-separated or multiple flags). e.g., cert-sign, crl-sign"`
	ExtKeyUsages []string `name:"eku" help:"Custom extended key usages (comma-separated or multiple flags). e.g., server-auth, client-auth"`
}

func InterCAPrompt(initial *InterCACmd) (*InterCACmd, error) {
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
				Description("Choose cryptographic actions this Intermediate CA is permitted to perform").
				Options(
					huh.NewOption("Certificate Signing (Default)", "cert-sign"),
					huh.NewOption("CRL Signing (Default)", "crl-sign"),
					huh.NewOption("Digital Signature", "digital-signature"),
					huh.NewOption("Content Commitment", "content-commitment"),
					huh.NewOption("Key Encipherment", "key-encipherment"),
					huh.NewOption("Data Encipherment", "data-encipherment"),
					huh.NewOption("Key Agreement", "key-agreement"),
				).Value(&keyUsages),
			huh.NewMultiSelect[string]().
				Title("Extended Key Usages (Optional)").
				Description("Define specific downstream usage restrictions for this Intermediate CA").
				Options(
					huh.NewOption("Any Purpose", "any"),
					huh.NewOption("Server Authentication", "server-auth"),
					huh.NewOption("Client Authentication", "client-auth"),
					huh.NewOption("Code Signing", "code-signing"),
					huh.NewOption("Email Protection", "email-protection"),
					huh.NewOption("Time Stamping", "time-stamping"),
					huh.NewOption("OCSP Signing", "ocsp-signing"),
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
	return &InterCACmd{
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

func (icc *InterCACmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	finalConfig := icc
	if icc.IT {
		promptResult, err := InterCAPrompt(icc)
		if err != nil {
			return fmt.Errorf("prompt cancelled or failed: %w", err)
		}
		finalConfig = promptResult
	} else {
		hours, err := utils.ParseTTLToHours(icc.TTL)
		if err != nil {
			return fmt.Errorf("invalid entry for --ttl/-t: %v", err)
		}
		finalConfig.TTL = strconv.Itoa(hours)

		if finalConfig.CommonName == "" {
			return fmt.Errorf("missing required flag: --common-name/--cn")
		}
		if finalConfig.KeyType == "" {
			return fmt.Errorf("missing required flag: --key-type/--algo")
		}
	}

	var issuerCert *x509.Certificate
	var keyName string
	if icc.ISerialNumber != "" && icc.ICommonName == "" {
		dbCert, err := query.GetCertBySN(ctx, icc.ISerialNumber)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
		keyName = dbCert.KeyName
		issuerCert, err = ParseCertificate([]byte(dbCert.CertificatePem))
		if err != nil {
			return err
		}
	} else if icc.ISerialNumber == "" && icc.ICommonName != "" {
		dbCert, err := query.GetCertByCN(ctx, icc.ICommonName)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
		keyName = dbCert.KeyName
		issuerCert, err = ParseCertificate([]byte(dbCert.CertificatePem))
		if err != nil {
			return err
		}
	} else {
		return errors.New("One flag can be selected at a time")
	}

	issuerKeys, err := query.GetKeyByName(ctx, keyName)
	if err != nil {
		return fmt.Errorf("failed to ger key: %w", err)
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
	interCaCert, err := domain.GetIntermediate(pkix.Name{
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
		return fmt.Errorf("cannot generate Intermediate CA Certificate: %w", err)
	}

	// -------------------------------- WRITING TO THE DATABASE --------------------------------------

	privBlobPem, pubPem, err := ReturnPrivPubPem(keyPair.PrivateKey, keyPair.PublicKey)
	if err != nil {
		return err
	}

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: interCaCert.Raw,
	})

	err = database.RunInTx(ctx, db, func(txQuerier base.Querier) error {
		key, err := query.CreateKeyPair(ctx, base.CreateKeyPairParams{
			Name:          interCaCert.Subject.CommonName,
			Algorithm:     finalConfig.KeyType,
			PrivateKeyPem: privBlobPem,
			PublicKeyPem:  pubPem,
		})
		if err != nil {
			return fmt.Errorf("failed to create Key Pair in the database: %w", err)
		}
		_, err = query.CreateCertificate(ctx, base.CreateCertificateParams{
			SerialNumber:                  interCaCert.SerialNumber.String(),
			CommonName:                    interCaCert.Subject.CommonName,
			Type:                          "INTERMEDIATE-CA",
			KeyName:                       key.Name,
			IssuerCertificateSerialNumber: sql.NullString{String: "", Valid: false},
			NotBefore:                     interCaCert.NotBefore,
			NotAfter:                      interCaCert.NotAfter,
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

	log.Println("Success: successfully Created Certificate and it's Key Pair.")

	return nil
}
```

---

## `app/cmd/gen_leaf.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/gen_leaf.go`
- **Size:** 11633 bytes

```go
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

	database "certman/db"

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
	KeyType            string   `name:"algo" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ecdsa-256" help:"key-type specifies the Key algorithm will be used to crear the keys and sign the Certificate."`
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
		return errors.New("One flag can be selected at a time either --isn or --icn")
	}

	issuerKeys, err := query.GetKeyByName(ctx, keyName)
	if err != nil {
		return fmt.Errorf("failed to ger key: %w", err)
	}

	issuerPrivateKey, _, err := ParseKeys([]byte(issuerKeys.PrivateKeyPem), []byte(issuerKeys.PublicKeyPem))
	if err != nil {
		return err
	}

	keyPair, err := domain.GetKey(domain.KeyType(finalConfig.KeyType))
	if err != nil {
		return fmt.Errorf("unsupported key type: %s", finalConfig.KeyType)
	}

	parent := domain.Certificate{
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
	}, ttl, keyPair, &parent, usages)
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

	err = database.RunInTx(ctx, db, func(txQuerier base.Querier) error {
		key, err := query.CreateKeyPair(ctx, base.CreateKeyPairParams{
			Name:          leafCert.Subject.CommonName,
			Algorithm:     finalConfig.KeyType,
			PrivateKeyPem: privBlobPem,
			PublicKeyPem:  pubPem,
		})
		if err != nil {
			return fmt.Errorf("failed to create Key Pair in the database: %w", err)
		}

		_, err = query.CreateCertificate(ctx, base.CreateCertificateParams{
			SerialNumber:                  leafCert.SerialNumber.String(),
			CommonName:                    leafCert.Subject.CommonName,
			Type:                          "LEAF",
			KeyName:                       key.Name,
			IssuerCertificateSerialNumber: sql.NullString{String: "", Valid: false},
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
```

---

## `app/cmd/helpers.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/helpers.go`
- **Size:** 2566 bytes

```go
package cmd

import (
	"certman/app/utils"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func EncodeToPem(bytes []byte, blockType string) (string, error) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: bytes,
	})

	if pemBytes == nil {
		return "", errors.New("cannot encode to pem")
	}

	return string(pemBytes), nil
}

func DecodeToPem(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM bytes")
	}
	return block.Bytes, nil
}

func ParseCertificate(pemBytes []byte) (*x509.Certificate, error) {
	certBytes, err := DecodeToPem(pemBytes)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed parse Certificate: %w", err)
	}
	return cert, nil
}

func ReturnPrivPubPem(privateKey any, publicKey any) (string, string, error) {
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	masterKey, err := utils.GetMasterKey()
	if err != nil {
		return "", "", fmt.Errorf("failed to get master key from os keyring: %w", err)
	}
	privBytesBlob, err := utils.Encrypt(privBytes, masterKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt private key: %w", err)
	}
	privBlobPem, err := EncodeToPem(privBytesBlob, "ENCRYPTED PRIVATE KEY")

	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubPem, err := EncodeToPem(pubBytes, "PUBLIC KEY")

	return privBlobPem, pubPem, nil
}

func DecryptPrivKey(privPem []byte) ([]byte, error) {
	privKey, err := DecodeToPem(privPem)
	if err != nil {
		return nil, err
	}

	masterKey, err := utils.GetMasterKey()
	if err != nil {
		return nil, err
	}

	decryptedPrivKey, err := utils.Decrypt(privKey, masterKey)
	if err != nil {
		return nil, err
	}

	return decryptedPrivKey, nil
}

func ParseKeys(privPem []byte, pubPem []byte) (any, any, error) {
	decryptedPrivKey, err := DecryptPrivKey(privPem)
	if err != nil {
		return nil, nil, err
	}
	pubKey, err := DecodeToPem(pubPem)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(decryptedPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to Marshal private key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to Marshal public key")
	}

	return privateKey, publicKey, nil
}
```

---

## `app/cmd/init.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/init.go`
- **Size:** 568 bytes

```go
package cmd

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"certman/app/utils"

	database "certman/db"

	_ "github.com/mattn/go-sqlite3"
)

type InitCmd struct{}

func (ic *InitCmd) Run() error {
	homDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not find user home directory: %w", err)
	}

	appDataPath := filepath.Join(homDir, ".certman")
	if err := database.InitializeDB(appDataPath); err != nil {
		return fmt.Errorf("Initialization failed: %w", err)
	}

	err = utils.InitMasterKey()
	if err != nil {
		return err
	}

	return nil
}
```

---

## `app/cmd/list.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/list.go`
- **Size:** 2889 bytes

```go
package cmd

import (
	database "certman/db"
	"certman/db/base"
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type ListCmd struct {
	Cert ListCertCmd `cmd:"" help:"Lists all the Certificates."`
	Key  ListKeyCmd  `cmd:"" help:"Lists all the Keys."`
}

type ListCertCmd struct {
	Limit  int `name:"limit" short:"l" help:"Limit specifies how many keys to show. if not given then it will everything."`
	Offset int `name:"offset" short:"o" help:"Skip first N Certificates."`
}

func (lcc *ListCertCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	var certs []base.ListCertificatesRow
	var err error

	if lcc.Limit == 0 && lcc.Offset == 0 {
		err = database.RunInTx(ctx, db, func(txQuerier base.Querier) error {
			count, err := query.TotalCerts(ctx)
			if err != nil {
				return fmt.Errorf("failed to calculate total Certificates: %w", err)
			}
			certs, err = query.ListCertificates(ctx, base.ListCertificatesParams{Limit: count, Offset: 0})
			if err != nil {
				return fmt.Errorf("failed to list Certificates: %w", err)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("transaction failed, data rolled back: %w", err)
		}
	} else {
		certs, err = query.ListCertificates(ctx, base.ListCertificatesParams{Limit: int64(lcc.Limit), Offset: int64(lcc.Offset)})
		if err != nil {
			return fmt.Errorf("failed to list the certificates: %w", err)
		}
	}

	// NOTE: Have to use a library for showing table on terminal
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("|  %s |  %s  |\n", "Serial Number", "Common Name")
	fmt.Println(strings.Repeat("-", 50))
	for _, cert := range certs {
		fmt.Printf("|  %s  |  %s  |\n", cert.SerialNumber, cert.CommonName)
		fmt.Println(strings.Repeat("-", 50))
	}

	return nil
}

type ListKeyCmd struct {
	Limit  int `name:"limit" short:"l" help:"Limit specifies how many keys to show. if not given then it will everything."`
	Offset int `name:"offset" short:"o" help:"Skip first N keys."`
}

func (lkc *ListKeyCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	var keys []string
	var err error

	if lkc.Limit == 0 && lkc.Offset == 0 {
		err = database.RunInTx(ctx, db, func(txQuerier base.Querier) error {
			count, err := query.TotalKeys(ctx)
			if err != nil {
				return fmt.Errorf("failed to calculate total Keys: %w", err)
			}
			keys, err = query.ListKeys(ctx, base.ListKeysParams{Limit: count, Offset: 0})
			if err != nil {
				return fmt.Errorf("failed to list Keys: %w", err)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("transaction failed, data rolled back: %w", err)
		}
	} else {
		keys, err = query.ListKeys(ctx, base.ListKeysParams{Limit: int64(lkc.Limit), Offset: int64(lkc.Offset)})
		if err != nil {
			return fmt.Errorf("failed to list Keys: %w", err)
		}
	}

	fmt.Printf("Keys:\n")
	for _, key := range keys {
		fmt.Printf("    \u2022 %s", key)
	}

	return nil
}
```

---

## `app/cmd/read.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/read.go`
- **Size:** 2428 bytes

```go
package cmd

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
)

type ReadCmd struct {
	Cert ReadCertCmd `cmd:"" help:"Reads Certificates from Database."`
	Key  ReadKeyCmd  `cmd:"" help:"Reads Key from Database."`
}

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
		return errors.New("exactly one flag (--sn or --cn) must be provided")
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
```

---

## `app/cmd/verify.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/verify.go`
- **Size:** 6325 bytes

```go
package cmd

import (
	"certman/db/base"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"time"
)

type VerifyCmd struct {
	Cert VerifyCertCmd `cmd:"" help:"Verify Certificate."`
	Key  VerifyKeyCmd  `cmd:"" help:"Verify Key Pair with Certificate."`
}

type VerifyCertCmd struct {
	SerialNumber string `name:"sn" help:"Serial Number of the Certificate. Either one can be selected."`
	CommonName   string `name:"cn" help:"Common Name of the Certificate. Either one can be selected"`
}

func (vcc *VerifyCertCmd) Run(ctx context.Context, query base.Querier) error {
	var cert *x509.Certificate
	var issuerCert *x509.Certificate
	var rootCert *x509.Certificate

	if vcc.SerialNumber != "" && vcc.CommonName == "" {
		dbCert, err := query.GetCertBySN(ctx, vcc.SerialNumber)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
		cert, err = ParseCertificate([]byte(dbCert.CertificatePem))
		if err != nil {
			return err
		}
	} else if vcc.SerialNumber == "" && vcc.CommonName != "" {
		dbCert, err := query.GetCertByCN(ctx, vcc.CommonName)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
		cert, err = ParseCertificate([]byte(dbCert.CertificatePem))
		if err != nil {
			return err
		}
	} else {
		return errors.New("One flag can be selected at a time")
	}

	if cert.Issuer.SerialNumber != "" {
		dbIssuerCert, err := query.GetCertBySN(ctx, cert.Issuer.SerialNumber)
		if err != nil {
			return fmt.Errorf("failed to get issuer Certificate: %w", err)
		}
		issuerCert, err = ParseCertificate([]byte(dbIssuerCert.CertificatePem))
		if err != nil {
			return err
		}
	}

	if issuerCert != nil {
		rootCert = issuerCert
		for {
			if rootCert.CheckSignatureFrom(rootCert) == nil {
				break
			}
			if rootCert.Issuer.SerialNumber == "" {
				break
			}
			dbRootCert, err := query.GetCertBySN(ctx, rootCert.Issuer.SerialNumber)
			if err != nil {
				return fmt.Errorf("failed to get next chain certificate: %w", err)
			}
			nextCert, err := ParseCertificate([]byte(dbRootCert.CertificatePem))
			if err != nil {
				return err
			}
			if nextCert.SerialNumber.String() == rootCert.SerialNumber.String() {
				break
			}
			rootCert = nextCert
		}
	}

	now := time.Now()
	if now.Before(cert.NotBefore) {
		log.Printf("Warning: Certificate is not valid yet! (Starts: %s)\n", cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		log.Printf("Warning: Certificate is EXPIRED! (Expired on: %s)\n", cert.NotAfter.Format(time.RFC3339))
	} else if cert.NotAfter.Sub(now) < (30 * 24 * time.Hour) {
		daysRemaining := int(cert.NotAfter.Sub(now).Hours() / 24)
		log.Printf("Warning: Certificate expires soon in %d days! (Expires on: %s)\n", daysRemaining, cert.NotAfter.Format(time.RFC3339))
	}

	rootPool := x509.NewCertPool()
	issuersPool := x509.NewCertPool()

	if issuerCert == nil {
		return errors.New("unable to verify chain: issuer certificate not found in database")
	}
	isRoot := issuerCert.CheckSignatureFrom(issuerCert) == nil

	if isRoot {
		rootPool.AddCert(issuerCert)
	} else {
		issuersPool.AddCert(issuerCert)
		rootPool.AddCert(rootCert)
	}

	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: issuersPool,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("chain verification failed: %w", err)
	}

	log.Println("Success: Certificate chain is valid and trusted!")
	log.Printf("Verified Chain depth: %d certificates in the trust chain.\n", len(chains[0]))

	return nil
}

type VerifyKeyCmd struct {
	SerialNumber string `name:"sn" help:"Serial Number of the Certificate which private key needs to be verified. Either one can be selected."`
	CommonName   string `name:"cn" help:"Common Name of the Certificate which private key needs to be verified. Either one can be selected"`
}

func (vkc *VerifyKeyCmd) Run(ctx context.Context, query base.Querier) error {
	var cert *x509.Certificate
	var keyName string

	if vkc.SerialNumber != "" && vkc.CommonName == "" {
		dbCert, err := query.GetCertBySN(ctx, vkc.SerialNumber)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
		keyName = dbCert.KeyName
		cert, err = ParseCertificate([]byte(dbCert.CertificatePem))
		if err != nil {
			return err
		}
	} else if vkc.SerialNumber == "" && vkc.CommonName != "" {
		dbCert, err := query.GetCertByCN(ctx, vkc.CommonName)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
		keyName = dbCert.KeyName
		cert, err = ParseCertificate([]byte(dbCert.CertificatePem))
		if err != nil {
			return err
		}
	} else {
		return errors.New("exactly one flag (--sn or --cn) must be provided")
	}

	keys, err := query.GetKeyByName(ctx, keyName)
	if err != nil {
		return fmt.Errorf("failed to get key: %w", err)
	}

	privateKey, _, err := ParseKeys([]byte(keys.PrivateKeyPem), []byte(keys.PublicKeyPem))
	if err != nil {
		return err
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return errors.New("key mismatch: certificate holds an RSA public key, but the private key is not RSA")
		}
		if !pub.Equal(&priv.PublicKey) {
			return errors.New("cryptographic mismatch: RSA private key does not belong to this certificate")
		}

	case *ecdsa.PublicKey:
		priv, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("key mismatch: certificate holds an ECDSA public key, but the private key is not ECDSA")
		}
		if !pub.Equal(&priv.PublicKey) {
			return errors.New("cryptographic mismatch: ECDSA private key does not belong to this certificate")
		}

	case ed25519.PublicKey:
		priv, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return errors.New("key mismatch: certificate holds an Ed25519 public key, but the private key is not Ed25519")
		}
		privPub, ok := priv.Public().(ed25519.PublicKey)
		if !ok || !pub.Equal(privPub) {
			return errors.New("cryptographic mismatch: Ed25519 private key does not belong to this certificate")
		}

	default:
		return fmt.Errorf("unsupported public key algorithm type: %T", cert.PublicKey)
	}

	log.Println("Success: The private key perfectly matches the certificate public key.")

	return nil
}
```

---

## `app/domain/cert.go`

- **Full path:** `/home/tassok/CLI/certman/app/domain/cert.go`
- **Size:** 5613 bytes

```go
package domain

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"certman/app/utils"
)

// GetBaseTemplate generates the basic certificate scaffolding.
func GetBaseTemplate(subject pkix.Name, serialNumber *big.Int, ttlInHour int, isCA bool) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(ttlInHour) * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true, // Crucial for CA validation
	}
}

// GetCA generates a root CA certificate with dynamic key usages.
func GetCA(subject pkix.Name, ttlInHour int, keyPair *KeyPair, usages *KeyUsageConfig) (*x509.Certificate, error) {
	serialNumber, err := utils.GetSerialNumber()
	if err != nil {
		return nil, err
	}

	template := GetBaseTemplate(subject, serialNumber, ttlInHour, true)

	// Apply dynamic key usages or fallback to standard CA defaults
	if usages != nil && len(usages.KeyUsages) > 0 {
		template.KeyUsage = 0
		for _, ku := range usages.KeyUsages {
			template.KeyUsage |= ku
		}
	} else {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	// Apply dynamic extended key usages if provided
	if usages != nil && len(usages.ExtKeyUsages) > 0 {
		template.ExtKeyUsage = usages.ExtKeyUsages
	}

	// Self-signed CA: Subject Key ID and Authority Key ID match
	skid, err := generateSKID(keyPair.PublicKey)
	if err != nil {
		return nil, err
	}
	template.SubjectKeyId = skid
	template.AuthorityKeyId = skid

	caBytes, err := x509.CreateCertificate(rand.Reader, template, template, keyPair.PublicKey, keyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse CA certificate: %w", err)
	}

	return caCert, nil
}

// GetIntermediate generates an intermediate CA certificate with dynamic key usages.
func GetIntermediate(subject pkix.Name, san SANs, ttlInHour int, keyPair *KeyPair, parent *Certificate, usages *KeyUsageConfig) (*x509.Certificate, error) {
	if parent == nil || !parent.Cert.IsCA {
		return nil, errors.New("invalid parent certificate: parent must be a valid CA")
	}

	serialNumber, err := utils.GetSerialNumber()
	if err != nil {
		return nil, err
	}

	template := GetBaseTemplate(subject, serialNumber, ttlInHour, true)

	// MaxPathLen constraints
	template.MaxPathLen = 0
	template.MaxPathLenZero = true // This intermediate can only sign leaf certs, not more CAs

	// Apply dynamic key usages or fallback to standard CA defaults
	if usages != nil && len(usages.KeyUsages) > 0 {
		template.KeyUsage = 0
		for _, ku := range usages.KeyUsages {
			template.KeyUsage |= ku
		}
	} else {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	// Apply dynamic extended key usages if provided
	if usages != nil && len(usages.ExtKeyUsages) > 0 {
		template.ExtKeyUsage = usages.ExtKeyUsages
	}

	template.DNSNames = san.DNSNames
	template.EmailAddresses = san.EmailAddresses
	template.IPAddresses = san.IPAddresses
	template.URIs = san.URIs

	// Key Identifiers
	template.SubjectKeyId, err = generateSKID(keyPair.PublicKey)
	if err != nil {
		return nil, err
	}
	template.AuthorityKeyId = parent.Cert.SubjectKeyId

	interBytes, err := x509.CreateCertificate(rand.Reader, template, parent.Cert, keyPair.PublicKey, parent.Keys.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate intermediate certificate: %w", err)
	}

	interCaCert, err := x509.ParseCertificate(interBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse intermediate certificate: %w", err)
	}

	return interCaCert, nil
}

// GetLeaf generates a leaf certificate with dynamic key usages.
func GetLeaf(subject pkix.Name, san SANs, ttlInHour int, keyPair *KeyPair, parent *Certificate, usages *KeyUsageConfig) (*x509.Certificate, error) {
	if parent == nil || !parent.Cert.IsCA {
		return nil, fmt.Errorf("invalid parent certificate: leaf must be signed by a CA/Intermediate")
	}

	serialNumber, err := utils.GetSerialNumber()
	if err != nil {
		return nil, err
	}

	template := GetBaseTemplate(subject, serialNumber, ttlInHour, false)

	// Apply dynamic key usages or fallback to standard Leaf defaults
	if usages != nil && len(usages.KeyUsages) > 0 {
		template.KeyUsage = 0
		for _, ku := range usages.KeyUsages {
			template.KeyUsage |= ku
		}
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}

	// Apply dynamic extended key usages or fallback to standard Server/Client Auth defaults
	if usages != nil && len(usages.ExtKeyUsages) > 0 {
		template.ExtKeyUsage = usages.ExtKeyUsages
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	template.DNSNames = san.DNSNames
	template.EmailAddresses = san.EmailAddresses
	template.IPAddresses = san.IPAddresses
	template.URIs = san.URIs

	// Key Identifiers
	template.SubjectKeyId, err = generateSKID(keyPair.PublicKey)
	if err != nil {
		return nil, err
	}
	template.AuthorityKeyId = parent.Cert.SubjectKeyId

	leafBytes, err := x509.CreateCertificate(rand.Reader, template, parent.Cert, keyPair.PublicKey, parent.Keys.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate leaf certificate: %w", err)
	}

	leafCert, err := x509.ParseCertificate(leafBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse leaf certificate: %w", err)
	}

	return leafCert, nil
}
```

---

## `app/domain/constants.go`

- **Full path:** `/home/tassok/CLI/certman/app/domain/constants.go`
- **Size:** 702 bytes

```go
package domain

import (
	"crypto/x509"
	"net"
	"net/url"
)

type KeyType string

const (
	RSA_2048   KeyType = "rsa-2048"
	RSA_4096   KeyType = "rsa-4096"
	ECDSA_P224 KeyType = "ecdsa-224"
	ECDSA_P256 KeyType = "ecdsa-256"
	ECDSA_P384 KeyType = "ecdsa-384"
	ECDSA_P521 KeyType = "ecdsa-521"
	ED25519    KeyType = "ed25519"
	UNKNOWN    KeyType = "UNKNOWN"
)

type KeyPair struct {
	PrivateKey any
	PublicKey  any
}

type Certificate struct {
	Cert *x509.Certificate
	Keys *KeyPair
}

type SANs struct {
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL
}

type KeyUsageConfig struct {
	KeyUsages    []x509.KeyUsage
	ExtKeyUsages []x509.ExtKeyUsage
}
```

---

## `app/domain/helpers.go`

- **Full path:** `/home/tassok/CLI/certman/app/domain/helpers.go`
- **Size:** 2033 bytes

```go
package domain

import (
	"crypto/elliptic"
	"crypto/sha1"
	"crypto/x509"
	"fmt"

	"certman/app/utils"
)

// Helper to get KeyPair based on the type
func GetKey(keyType KeyType) (*KeyPair, error) {
	switch keyType {
	case RSA_2048:
		privKey, pubKey, err := utils.GetRSAKey(2048)
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case RSA_4096:
		privKey, pubKey, err := utils.GetRSAKey(4096)
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ECDSA_P224:
		privKey, pubKey, err := utils.GetECDSAKey(elliptic.P224())
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ECDSA_P256:
		privKey, pubKey, err := utils.GetECDSAKey(elliptic.P256())
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ECDSA_P384:
		privKey, pubKey, err := utils.GetECDSAKey(elliptic.P384())
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ECDSA_P521:
		privKey, pubKey, err := utils.GetECDSAKey(elliptic.P521())
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ED25519:
		privKey, pubKey, err := utils.GetED25519Key()
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// Helper to generate a Subject Key Identifier from a public key
func generateSKID(pubKey any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SKID using public key: %w", err)
	}
	// Classic RFC 5280 method 1: SHA-1 hash of the value of the BIT STRING subjectPublicKey
	hasher := sha1.New()
	hasher.Write(der)
	return hasher.Sum(nil), nil
}
```


---

## `app/utils/cipher.go`

- **Full path:** `/home/tassok/CLI/certman/app/utils/cipher.go`
- **Size:** 1183 bytes

```go
package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

func Encrypt(plaintext, masterKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate cipher block: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cannot generate gcm AEAD: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cannot generate secure nonce: %w", err)
	}

	return aesGCM.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(ciphertext, masterKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate cipher block: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cannot generate gcm AEAD: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("cipher is too short: %v", len(ciphertext))
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesGCM.Open(nil, nonce, actualCiphertext, nil)
}
```


---

## `app/utils/key.go`

- **Full path:** `/home/tassok/CLI/certman/app/utils/key.go`
- **Size:** 1497 bytes

```go
package utils

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
)

func GetRSAKey(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate rsa key: %w", err)
	}
	return privKey, &privKey.PublicKey, nil
}

func GetECDSAKey(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate ecdsa key: %w", err)
	}
	return privKey, &privKey.PublicKey, nil
}

func GetED25519Key() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate ed25519 key: %v", err)
	}
	return privKey, pubKey, nil
}

func ParseKey(privKey, pubKey []byte) (any, any, error) {
	parsedPub, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot parse PKIX public key: %w", err)
	}

	if parsedPriv, err := x509.ParsePKCS8PrivateKey(privKey); err == nil {
		return parsedPriv, parsedPub, nil
	}
	if parsedPriv, err := x509.ParsePKCS1PrivateKey(privKey); err == nil {
		return parsedPriv, parsedPub, nil
	}
	if parsedPriv, err := x509.ParseECPrivateKey(privKey); err == nil {
		return parsedPriv, parsedPub, nil
	}

	return nil, nil, errors.New("unknown key type")
}
```


---

## `app/utils/keyring.go`

- **Full path:** `/home/tassok/CLI/certman/app/utils/keyring.go`
- **Size:** 1477 bytes

```go
package utils

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

const (
	serviceName = "certman"
	accountName = "master-key"
)

// InitMasterKey generates a secure 32-byte key and stores it in Fedora's keyring
func InitMasterKey() error {
	// Check if a key already exists to prevent accidental overwriting
	_, err := keyring.Get(serviceName, accountName)
	if err == nil {
		return errors.New("application is already initialized with a master key")
	}

	// Generate a secure 32-byte (256-bit) AES key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return fmt.Errorf("cannot generate secure bytes: %w", err)
	}
	masterKeyHex := hex.EncodeToString(keyBytes)

	// Save to OS Keyring
	err = keyring.Set(serviceName, accountName, masterKeyHex)
	if err != nil {
		return fmt.Errorf("cannot store key in OS keyring: %w", err)
	}
	return nil
}

// GetMasterKey silently retrieves the key from the OS keyring for cryptography
func GetMasterKey() ([]byte, error) {
	keyHex, err := keyring.Get(serviceName, accountName)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, errors.New("app not initialized. Please run the init command first")
		}
		return nil, fmt.Errorf("cannot fetch key from OS keyring: %v", err)
	}

	// Decode back to raw bytes for AES-GCM encryption/decryption
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}
```

---

## `app/utils/util.go`

- **Full path:** `/home/tassok/CLI/certman/app/utils/util.go`
- **Size:** 4609 bytes

```go
package utils

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func ToNetIP(addr string) (net.IP, error) {
	parsedIP := net.ParseIP(addr)
	if parsedIP == nil {
		return nil, errors.New("unknown or invalid ip address")
	}

	return parsedIP, nil
}

func ToNetIPs(addrs []string) []net.IP {
	var netIPs []net.IP

	for _, ip := range addrs {
		netIP, err := ToNetIP(ip)
		if err != nil {
			log.Printf("skipping invalid IP string: %s\n", ip)
			continue
		}
		netIPs = append(netIPs, netIP)
	}
	return netIPs
}

func ToURL(s string) (*url.URL, error) {
	parsedUrl, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("unknown or invalid url")
	}

	return parsedUrl, nil
}

func ToURLs(urls []string) []*url.URL {
	var urlURLs []*url.URL

	for _, urlStr := range urls {
		u, err := ToURL(urlStr)
		if err != nil {
			log.Printf("skipping invalid URL string: %s\n", urlStr)
			continue
		}
		urlURLs = append(urlURLs, u)
	}
	return urlURLs
}

func ToPem(bytes []byte, blockType string) []byte {
	block := pem.Block{
		Bytes: bytes,
		Type:  blockType,
	}
	pemBytes := pem.EncodeToMemory(&block)

	return pemBytes
}

func GetSerialNumber() (*big.Int, error) {
	sNumLim := new(big.Int).Lsh(big.NewInt(1), 128)
	sNum, err := rand.Int(rand.Reader, sNumLim)
	if err != nil {
		return nil, fmt.Errorf("cannot generate serial number: %w", err)
	}
	return sNum, nil
}

func JoinHomeDir(filePath string) (string, error) {
	if strings.HasPrefix(filePath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot get home directory: %w", err)
		}
		resolvedPath := filepath.Join(home, filePath[2:])
		return resolvedPath, nil
	}
	return filePath, nil
}

func SplitCSV(in string) []string {
	if strings.TrimSpace(in) == "" {
		return nil
	}
	var out []string
	for segment := range strings.SplitSeq(in, ",") {
		if trimmed := strings.TrimSpace(segment); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// ToSnakeCase converts a string to lowercase and replaces spaces/special characters with underscores.
func ToSnakeCase(str string) string {
	lower := strings.ToLower(strings.TrimSpace(str))

	// 2. Replace one or more consecutive spaces, hyphens, or special chars with a single underscore
	reg := regexp.MustCompile(`[\s\-_]+`)
	snake := reg.ReplaceAllString(lower, "_")

	return snake
}

func ParseKeyUsages(usages []string) []x509.KeyUsage {
	var out []x509.KeyUsage
	m := map[string]x509.KeyUsage{
		"digital-signature":  x509.KeyUsageDigitalSignature,
		"content-commitment": x509.KeyUsageContentCommitment,
		"key-encipherment":   x509.KeyUsageKeyEncipherment,
		"data-encipherment":  x509.KeyUsageDataEncipherment,
		"key-agreement":      x509.KeyUsageKeyAgreement,
		"cert-sign":          x509.KeyUsageCertSign,
		"crl-sign":           x509.KeyUsageCRLSign,
		"encipher-only":      x509.KeyUsageEncipherOnly,
		"decipher-only":      x509.KeyUsageDecipherOnly,
	}
	for _, u := range usages {
		if ku, exists := m[strings.ToLower(strings.TrimSpace(u))]; exists {
			out = append(out, ku)
		}
	}
	return out
}

func ParseExtKeyUsages(usages []string) []x509.ExtKeyUsage {
	var out []x509.ExtKeyUsage
	m := map[string]x509.ExtKeyUsage{
		"any":              x509.ExtKeyUsageAny,
		"server-auth":      x509.ExtKeyUsageServerAuth,
		"client-auth":      x509.ExtKeyUsageClientAuth,
		"code-signing":     x509.ExtKeyUsageCodeSigning,
		"email-protection": x509.ExtKeyUsageEmailProtection,
		"time-stamping":    x509.ExtKeyUsageTimeStamping,
		"ocsp-signing":     x509.ExtKeyUsageOCSPSigning,
	}
	for _, u := range usages {
		if eku, exists := m[strings.ToLower(strings.TrimSpace(u))]; exists {
			out = append(out, eku)
		}
	}
	return out
}

var durationRegex = regexp.MustCompile(`^(\d+)([hdy])$`)

// ParseTTLToHours parses duration strings like "1000h", "30d", "10y" into total hours.
func ParseTTLToHours(ttlStr string) (int, error) {
	matches := durationRegex.FindStringSubmatch(ttlStr)
	if len(matches) != 3 {
		return 0, fmt.Errorf("invalid duration format %q: must be a number followed by 'h', 'd', or 'y' (e.g., 1000h, 30d, 10y)", ttlStr)
	}

	value, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, fmt.Errorf("invalid number in duration: %v", err)
	}

	unit := matches[2]
	switch unit {
	case "h":
		return value, nil
	case "d":
		return value * 24, nil
	case "y":
		// Approximating a year as 365 days (8760 hours)
		return value * 24 * 365, nil
	default:
		return 0, fmt.Errorf("unsupported time unit: %s", unit)
	}
}
```


---

## `db/base/db.go`

- **Full path:** `/home/tassok/CLI/certman/db/base/db.go`
- **Size:** 597 bytes

```go
// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.31.1

package base

import (
	"context"
	"database/sql"
)

type DBTX interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

func New(db DBTX) *Queries {
	return &Queries{db: db}
}

type Queries struct {
	db DBTX
}

func (q *Queries) WithTx(tx *sql.Tx) *Queries {
	return &Queries{
		db: tx,
	}
}
```

---

## `db/base/models.go`

- **Full path:** `/home/tassok/CLI/certman/db/base/models.go`
- **Size:** 1337 bytes

```go
// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.31.1

package base

import (
	"database/sql"
	"time"
)

type Certificate struct {
	ID                            int64          `json:"id"`
	SerialNumber                  string         `json:"serial_number"`
	CommonName                    string         `json:"common_name"`
	Type                          string         `json:"type"`
	KeyName                       string         `json:"key_name"`
	IssuerCertificateSerialNumber sql.NullString `json:"issuer_certificate_serial_number"`
	NotBefore                     time.Time      `json:"not_before"`
	NotAfter                      time.Time      `json:"not_after"`
	IsRevoked                     sql.NullInt64  `json:"is_revoked"`
	RevocationReason              sql.NullInt64  `json:"revocation_reason"`
	RevocationTime                sql.NullTime   `json:"revocation_time"`
	CertificatePem                string         `json:"certificate_pem"`
	CreatedAt                     sql.NullTime   `json:"created_at"`
}

type Key struct {
	ID            int64        `json:"id"`
	Name          string       `json:"name"`
	Algorithm     string       `json:"algorithm"`
	PrivateKeyPem string       `json:"private_key_pem"`
	PublicKeyPem  string       `json:"public_key_pem"`
	CreatedAt     sql.NullTime `json:"created_at"`
}
```

---

## `db/base/querier.go`

- **Full path:** `/home/tassok/CLI/certman/db/base/querier.go`
- **Size:** 806 bytes

```go
// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.31.1

package base

import (
	"context"
)

type Querier interface {
	CreateCertificate(ctx context.Context, arg CreateCertificateParams) (Certificate, error)
	CreateKeyPair(ctx context.Context, arg CreateKeyPairParams) (Key, error)
	GetCertByCN(ctx context.Context, commonName string) (Certificate, error)
	GetCertBySN(ctx context.Context, serialNumber string) (Certificate, error)
	GetKeyByName(ctx context.Context, name string) (Key, error)
	ListCertificates(ctx context.Context, arg ListCertificatesParams) ([]ListCertificatesRow, error)
	ListKeys(ctx context.Context, arg ListKeysParams) ([]string, error)
	TotalCerts(ctx context.Context) (int64, error)
	TotalKeys(ctx context.Context) (int64, error)
}

var _ Querier = (*Queries)(nil)
```

---

## `db/base/query.sql.go`

- **Full path:** `/home/tassok/CLI/certman/db/base/query.sql.go`
- **Size:** 6702 bytes

```go
// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.31.1
// source: query.sql

package base

import (
	"context"
	"database/sql"
	"time"
)

const createCertificate = `-- name: CreateCertificate :one
INSERT INTO certificates (
    serial_number,
    common_name,
    type,
    key_name,
    issuer_certificate_serial_number,
    not_before,
    not_after,
    certificate_pem
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?
)
RETURNING id, serial_number, common_name, type, key_name, issuer_certificate_serial_number, not_before, not_after, is_revoked, revocation_reason, revocation_time, certificate_pem, created_at
`

type CreateCertificateParams struct {
	SerialNumber                  string         `json:"serial_number"`
	CommonName                    string         `json:"common_name"`
	Type                          string         `json:"type"`
	KeyName                       string         `json:"key_name"`
	IssuerCertificateSerialNumber sql.NullString `json:"issuer_certificate_serial_number"`
	NotBefore                     time.Time      `json:"not_before"`
	NotAfter                      time.Time      `json:"not_after"`
	CertificatePem                string         `json:"certificate_pem"`
}

func (q *Queries) CreateCertificate(ctx context.Context, arg CreateCertificateParams) (Certificate, error) {
	row := q.db.QueryRowContext(ctx, createCertificate,
		arg.SerialNumber,
		arg.CommonName,
		arg.Type,
		arg.KeyName,
		arg.IssuerCertificateSerialNumber,
		arg.NotBefore,
		arg.NotAfter,
		arg.CertificatePem,
	)
	var i Certificate
	err := row.Scan(
		&i.ID,
		&i.SerialNumber,
		&i.CommonName,
		&i.Type,
		&i.KeyName,
		&i.IssuerCertificateSerialNumber,
		&i.NotBefore,
		&i.NotAfter,
		&i.IsRevoked,
		&i.RevocationReason,
		&i.RevocationTime,
		&i.CertificatePem,
		&i.CreatedAt,
	)
	return i, err
}

const createKeyPair = `-- name: CreateKeyPair :one
INSERT INTO keys (
    name,
    algorithm,
    private_key_pem,
    public_key_pem
) VALUES (
    ?, ?, ?, ?
)
RETURNING id, name, algorithm, private_key_pem, public_key_pem, created_at
`

type CreateKeyPairParams struct {
	Name          string `json:"name"`
	Algorithm     string `json:"algorithm"`
	PrivateKeyPem string `json:"private_key_pem"`
	PublicKeyPem  string `json:"public_key_pem"`
}

func (q *Queries) CreateKeyPair(ctx context.Context, arg CreateKeyPairParams) (Key, error) {
	row := q.db.QueryRowContext(ctx, createKeyPair,
		arg.Name,
		arg.Algorithm,
		arg.PrivateKeyPem,
		arg.PublicKeyPem,
	)
	var i Key
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Algorithm,
		&i.PrivateKeyPem,
		&i.PublicKeyPem,
		&i.CreatedAt,
	)
	return i, err
}

const getCertByCN = `-- name: GetCertByCN :one
SELECT id, serial_number, common_name, type, key_name, issuer_certificate_serial_number, not_before, not_after, is_revoked, revocation_reason, revocation_time, certificate_pem, created_at FROM certificates WHERE common_name = ?
`

func (q *Queries) GetCertByCN(ctx context.Context, commonName string) (Certificate, error) {
	row := q.db.QueryRowContext(ctx, getCertByCN, commonName)
	var i Certificate
	err := row.Scan(
		&i.ID,
		&i.SerialNumber,
		&i.CommonName,
		&i.Type,
		&i.KeyName,
		&i.IssuerCertificateSerialNumber,
		&i.NotBefore,
		&i.NotAfter,
		&i.IsRevoked,
		&i.RevocationReason,
		&i.RevocationTime,
		&i.CertificatePem,
		&i.CreatedAt,
	)
	return i, err
}

const getCertBySN = `-- name: GetCertBySN :one
SELECT id, serial_number, common_name, type, key_name, issuer_certificate_serial_number, not_before, not_after, is_revoked, revocation_reason, revocation_time, certificate_pem, created_at FROM certificates WHERE serial_number = ?
`

func (q *Queries) GetCertBySN(ctx context.Context, serialNumber string) (Certificate, error) {
	row := q.db.QueryRowContext(ctx, getCertBySN, serialNumber)
	var i Certificate
	err := row.Scan(
		&i.ID,
		&i.SerialNumber,
		&i.CommonName,
		&i.Type,
		&i.KeyName,
		&i.IssuerCertificateSerialNumber,
		&i.NotBefore,
		&i.NotAfter,
		&i.IsRevoked,
		&i.RevocationReason,
		&i.RevocationTime,
		&i.CertificatePem,
		&i.CreatedAt,
	)
	return i, err
}

const getKeyByName = `-- name: GetKeyByName :one
SELECT id, name, algorithm, private_key_pem, public_key_pem, created_at FROM keys WHERE name = ?
`

func (q *Queries) GetKeyByName(ctx context.Context, name string) (Key, error) {
	row := q.db.QueryRowContext(ctx, getKeyByName, name)
	var i Key
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Algorithm,
		&i.PrivateKeyPem,
		&i.PublicKeyPem,
		&i.CreatedAt,
	)
	return i, err
}

const listCertificates = `-- name: ListCertificates :many
SELECT serial_number, common_name FROM certificates LIMIT ? OFFSET ?
`

type ListCertificatesParams struct {
	Limit  int64 `json:"limit"`
	Offset int64 `json:"offset"`
}

type ListCertificatesRow struct {
	SerialNumber string `json:"serial_number"`
	CommonName   string `json:"common_name"`
}

func (q *Queries) ListCertificates(ctx context.Context, arg ListCertificatesParams) ([]ListCertificatesRow, error) {
	rows, err := q.db.QueryContext(ctx, listCertificates, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ListCertificatesRow
	for rows.Next() {
		var i ListCertificatesRow
		if err := rows.Scan(&i.SerialNumber, &i.CommonName); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const listKeys = `-- name: ListKeys :many
SELECT name FROM keys LIMIT ? OFFSET ?
`

type ListKeysParams struct {
	Limit  int64 `json:"limit"`
	Offset int64 `json:"offset"`
}

func (q *Queries) ListKeys(ctx context.Context, arg ListKeysParams) ([]string, error) {
	rows, err := q.db.QueryContext(ctx, listKeys, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		items = append(items, name)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const totalCerts = `-- name: TotalCerts :one
SELECT COUNT(*) AS total_count FROM certificates
`

func (q *Queries) TotalCerts(ctx context.Context) (int64, error) {
	row := q.db.QueryRowContext(ctx, totalCerts)
	var total_count int64
	err := row.Scan(&total_count)
	return total_count, err
}

const totalKeys = `-- name: TotalKeys :one
SELECT COUNT(*) AS total_keys FROM keys
`

func (q *Queries) TotalKeys(ctx context.Context) (int64, error) {
	row := q.db.QueryRowContext(ctx, totalKeys)
	var total_keys int64
	err := row.Scan(&total_keys)
	return total_keys, err
}
```

---

## `db/conn.go`

- **Full path:** `/home/tassok/CLI/certman/db/conn.go`
- **Size:** 973 bytes

```go
package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// GetConnection opens a connection to the SQLite database file at the given path,
// enforces constraints, configures the pool for performance, and returns the handle.
func GetConnection(dbPath string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL", dbPath)

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Enforce Foreign Keys
	_, err = db.Exec("PRAGMA foreign_keys = ON;")
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable foreign key support: %w", err)
	}

	// Connection Pool Settings optimized for sequential CLI usage with transactions
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(1 * time.Hour)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}
```

---

## `db/embed.go`

- **Full path:** `/home/tassok/CLI/certman/db/embed.go`
- **Size:** 70 bytes

```go
package db

import _ "embed"

//go:embed schema.sql
var Schema string
```

---

## `db/init.go`

- **Full path:** `/home/tassok/CLI/certman/db/init.go`
- **Size:** 916 bytes

```go
package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// InitializeDB handles creating the folder, the file, and running the schema
func InitializeDB(dbDir string) error {
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	dbPath := filepath.Join(dbDir, "certman.db")
	fmt.Printf("Initializing database at: %s\n", dbPath)

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	_, err = db.Exec("PRAGMA foreign_keys = ON;")
	if err != nil {
		return fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	_, err = db.ExecContext(context.Background(), Schema)
	if err != nil {
		return fmt.Errorf("failed to execute schema initialization: %w", err)
	}

	log.Println("Success: Database structures successfully populated!")
	return nil
}
```

---

## `db/tx.go`

- **Full path:** `/home/tassok/CLI/certman/db/tx.go`
- **Size:** 665 bytes

```go
package db

import (
	"certman/db/base"
	"context"
	"database/sql"
	"fmt"
)

// RunInTx wraps operations inside an atomic SQLite transaction
func RunInTx(ctx context.Context, db *sql.DB, fn func(txQuerier base.Querier) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	txQueries := base.New(tx)

	err = fn(txQueries)
	if err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("tx error: %v, rollback failed: %v", err, rbErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
```

---

## `main.go`

- **Full path:** `/home/tassok/CLI/certman/main.go`
- **Size:** 2267 bytes

```go
package main

import (
	"certman/app/cmd"
	"certman/app/utils"
	"certman/db"
	database "certman/db"
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

	dbPath := filepath.Join(home, ".certman/certman.db")
	_, err = os.Stat(dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			dirPath := filepath.Dir(dbPath)
			if err := database.InitializeDB(dirPath); err != nil {
				log.Fatalf("Initialization failed: %v", err)
			}
		} else {
			// Only fire an exception if the error is an OS lock or permission problem
			log.Fatalf("something occurred while checking the file: %v", err)
		}
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
		kong.BindTo(ctx, (*context.Context)(nil)),
		kong.Bind(sqlConn),
		kong.BindTo(query, (*base.Querier)(nil)),
	)

	err = Kongctx.Run()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
```

---


*Total files processed: 31*
