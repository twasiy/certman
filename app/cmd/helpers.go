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

	privateKey, err := x509.MarshalPKCS8PrivateKey(decryptedPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to Marshal private key")
	}
	publicKey, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to Marshal public key")
	}

	return privateKey, publicKey, nil
}
