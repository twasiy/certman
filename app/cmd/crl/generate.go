package crl

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

type GenerateCmd struct {
	ISerialNumber string `name:"isn" xor:"issuer" help:"Serial Number of the Issuer Certificate."`
	ICommonName   string `name:"icn" xor:"issuer" help:"Common Name of the Issuer Certificate."`
	TTL           string `name:"ttl" short:"t" default:"168h" required:"Next Update time for CRL (e.g., 168h, 7d, 10y)"`
}

func (gc *GenerateCmd) Run(ctx context.Context, query base.Querier) error {
	issuerDBCert, err := gc.fetchCertificate(ctx, query)
	if err != nil {
		return err
	}

	issuerCert, err := utils.ParseCertificate([]byte(issuerDBCert.CertificatePem))
	if err != nil {
		return err
	}

	if issuerDBCert.IsRevoked.Valid && issuerDBCert.IsRevoked.Int64 == 1 {
		return fmt.Errorf("couldn't generate CRL: Issuer itself is Revoked")
	}
	revokedCerts, err := query.GetRevokedCertificates(ctx, sql.NullString{String: issuerDBCert.SerialNumber, Valid: true})
	if err != nil {
		return fmt.Errorf("could not get Revoked Certificates: %w", err)
	}

	if len(revokedCerts) <= 0 {
		return fmt.Errorf("no Certificate has been Revoked from this Issuer")
	}

	latestCRLNumber, err := query.GetLatestCRLNumber(ctx, issuerDBCert.SerialNumber)
	var nextCRLNumber int64 = 1
	if err == nil {
		nextCRLNumber = latestCRLNumber + 1
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to get latest CRL number: %w", err)
	}

	issuerKey, err := query.GetKeyByName(ctx, issuerDBCert.KeyName)
	if err != nil {
		return fmt.Errorf("failed to fetch issuer private key (%s): %w", issuerDBCert.KeyName, err)
	}

	rawKey, _, err := utils.ParseKeys([]byte(issuerKey.PrivateKeyPem), []byte(issuerKey.PublicKeyPem))
	if err != nil {
		return err
	}

	issuerPrivateKey, ok := rawKey.(crypto.Signer)
	if !ok {
		return errors.New("parsed private key does not implement crypto.Signer")
	}

	now := time.Now()
	ttlHours, err := utils.ParseTTLToHours(gc.TTL)
	if err != nil {
		return err
	}
	nextUpdate := now.Add(time.Duration(ttlHours) * time.Hour)

	revokedInputs, err := gc.mapRevokedCerts(revokedCerts, now)
	if err != nil {
		return err
	}

	crlTemplate := x509.RevocationList{
		SignatureAlgorithm:  issuerCert.SignatureAlgorithm,
		Number:              big.NewInt(nextCRLNumber),
		ThisUpdate:          now,
		NextUpdate:          nextUpdate,
		RevokedCertificates: revokedInputs,
	}

	// ----------------------------- WRITING TO THE DATABASE -------------------------------------

	crlDER, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, issuerCert, issuerPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to sign CRL: %w", err)
	}

	crlPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})
	generatedCrlPem := string(crlPEMBlock)

	_, err = query.CreateCRL(ctx, base.CreateCRLParams{
		Name:               formatCRLName(issuerCert.Subject.CommonName, now),
		CrlNumber:          nextCRLNumber,
		IssuerSerialNumber: issuerDBCert.SerialNumber,
		ThisUpdate:         now,
		NextUpdate:         nextUpdate,
		CrlPem:             generatedCrlPem,
	})
	if err != nil {
		return fmt.Errorf("failed to save generated CRL to database: %w", err)
	}
	return nil
}

func (gc *GenerateCmd) fetchCertificate(ctx context.Context, query base.Querier) (*base.Certificate, error) {
	var issuerDBCert base.Certificate
	var err error

	if gc.ISerialNumber != "" && gc.ICommonName == "" {
		issuerDBCert, err = query.GetCertificateBySN(ctx, gc.ISerialNumber)
		if err != nil {
			return nil, fmt.Errorf("failed to get Certificate: %w", err)
		}
	} else if gc.ISerialNumber == "" && gc.ICommonName != "" {
		issuerDBCert, err = query.GetCertificateByCN(ctx, gc.ICommonName)
		if err != nil {
			return nil, fmt.Errorf("failed to get Certificate: %w", err)
		}
	} else {
		return nil, errors.New("exactly one flag (--sn or --cn) must be provided")
	}
	return &issuerDBCert, nil
}

func (gc *GenerateCmd) mapRevokedCerts(revokedCerts []base.Certificate, now time.Time) ([]pkix.RevokedCertificate, error) {
	var revokedInputs []pkix.RevokedCertificate

	// Object Identifier (OID) for CRL Reason Code extension
	oidExtensionReasonCode := []int{2, 5, 29, 21}

	for _, rc := range revokedCerts {
		serialInt := new(big.Int)
		_, success := serialInt.SetString(rc.SerialNumber, 16)
		if !success {
			_, success = serialInt.SetString(rc.SerialNumber, 10)
			if !success {
				return nil, fmt.Errorf("failed to parse certificate serial number: %s", rc.SerialNumber)
			}
		}

		revTime := now
		if rc.RevocationTime.Valid {
			revTime = rc.RevocationTime.Time
		}

		var extensions []pkix.Extension

		// If a specific revocation reason is provided, pack it into an ASN.1 enumerated extension
		if rc.RevocationReason.Valid && rc.RevocationReason.Int64 > 0 {
			// ASN.1 ENUMERATED value encoding for the reason code
			reasonBytes := []byte{0x0a, 0x01, byte(rc.RevocationReason.Int64)}

			extensions = append(extensions, pkix.Extension{
				Id:       oidExtensionReasonCode,
				Critical: false,
				Value:    reasonBytes,
			})
		}

		revokedInputs = append(revokedInputs, pkix.RevokedCertificate{
			SerialNumber:   serialInt,
			RevocationTime: revTime,
			Extensions:     extensions,
		})
	}
	return revokedInputs, nil
}

// formatCRLName creates an identifier string like "MyCA_20260720_045357"
func formatCRLName(commonName string, now time.Time) string {
	sanitizedName := strings.ReplaceAll(commonName, " ", "_")

	// Formats the timestamp to a standard, sortable string layout (YYYYMMDD_HHMMSS)
	timestamp := now.Format("20060102_150405")

	return fmt.Sprintf("%s_%s", sanitizedName, timestamp)
}
