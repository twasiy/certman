package utils

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

type KeyType int

const (
	PUBLIC KeyType = iota
	PRIVATE
)

// WriteCert saves the certificate bytes into a standard PEM encoded certificate file
// filePath can be linux path, relative path, absolute path or just file name
func WriteCert(filePath string, certBytes []byte) error {
	// Certificates are public data, standard 0644 permissions are fine
	return write(filePath, "CERTIFICATE", certBytes, 0o644)
}

// WriteKey takes a concrete key (e.g., *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey)
// and dynamically handles legacy or PKCS#8 formatting.
func WriteKey(filePath string, key any, keyType KeyType, usePKCS8 bool, usePKIX bool, useCipher bool) error {
	if keyType == PUBLIC && usePKIX {
		pubBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return fmt.Errorf("cannot marshal public key: %w", err)
		}
		return write(filePath, "PUBLIC KEY", pubBytes, 0o644)
	}
	if keyType == PUBLIC && !usePKIX {
		pubBytes := x509.MarshalPKCS1PublicKey(key.(*rsa.PublicKey))
		return write(filePath, "RSA PUBLIC KEY", pubBytes, 0o644)
	}

	// For PRIVATE keys:
	var blockType string
	var privBytes []byte
	var err error

	if usePKCS8 {
		blockType = "PRIVATE KEY"
		privBytes, err = x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return fmt.Errorf("cannot marshal to PKCS#8: %w", err)
		}
	} else {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			blockType = "RSA PRIVATE KEY"
			privBytes = x509.MarshalPKCS1PrivateKey(k)
		case *ecdsa.PrivateKey:
			blockType = "EC PRIVATE KEY"
			privBytes, err = x509.MarshalECPrivateKey(k)
			if err != nil {
				return fmt.Errorf("cannot marshal EC key: %w", err)
			}
		default:
			blockType = "PRIVATE KEY"
			privBytes, err = x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return fmt.Errorf("cannot marshal to PKCS#8: %w", err)
			}
		}
	}
	if useCipher {
		masterKey, err := GetMasterKey()
		if err != nil {
			return fmt.Errorf("failed to retrieve master key for encryption: %w", err)
		}
		encryptedBytes, err := Encrypt(privBytes, masterKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt private key: %w", err)
		}
		privBytes = encryptedBytes
		blockType = "ENCRYPTED " + blockType
	}

	return write(filePath, blockType, privBytes, 0o600)
}

// write is a generic helper to write PEM blocks to disk
func write(filePath string, blockType string, bytes []byte, perm os.FileMode) error {
	path, err := JoinHomeDir(filePath)
	if err != nil {
		return err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: bytes,
	})
	if pemBytes == nil {
		return fmt.Errorf("failed to encode PEM block for type: %s", blockType)
	}

	err = os.WriteFile(path, pemBytes, perm)
	if err != nil {
		return fmt.Errorf("cannot write to the file : %w", err)
	}

	log.Printf("Success: successfully created %s\n", path)
	return nil
}
