package key

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
)

type VerifyCmd struct {
	SerialNumber string `name:"sn" xor:"own" help:"Serial Number of the Certificate which private key needs to be verified."`
	CommonName   string `name:"cn" xor:"own" help:"Common Name of the Certificate which private key needs to be verified."`
}

func (vc *VerifyCmd) Run(ctx context.Context, query base.Querier) error {
	var cert *x509.Certificate
	var keyName string

	if vc.SerialNumber != "" && vc.CommonName == "" {
		dbCert, err := query.GetCertificateBySN(ctx, vc.SerialNumber)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
		keyName = dbCert.KeyName
		cert, err = utils.ParseCertificate([]byte(dbCert.CertificatePem))
		if err != nil {
			return err
		}
	} else if vc.SerialNumber == "" && vc.CommonName != "" {
		dbCert, err := query.GetCertificateByCN(ctx, vc.CommonName)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
		keyName = dbCert.KeyName
		cert, err = utils.ParseCertificate([]byte(dbCert.CertificatePem))
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

	privateKey, _, err := utils.ParseKeys([]byte(keys.PrivateKeyPem), []byte(keys.PublicKeyPem))
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
