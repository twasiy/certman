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
		for rootCert.Issuer.SerialNumber != "" {
			dbRootCert, err := query.GetCertBySN(ctx, rootCert.Issuer.SerialNumber)
			if err != nil {
				return fmt.Errorf("failed to get root Certificate: %w", err)
			}
			rootCert, err = ParseCertificate([]byte(dbRootCert.CertificatePem))
			if err != nil {
				return err
			}
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
		return errors.New("One flag can be selected at a time")
	}

	keys, err := query.GetKeyByName(ctx, keyName)
	if err != nil {
		return fmt.Errorf("failed to ger key: %w", err)
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
