package bundle

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// GetPEMBundle takes a private key, leaf cert, and CA chain,
// and returns a single concatenated PEM byte slice.
func GetPEMBundle(privateKey crypto.PrivateKey, leafCert *x509.Certificate, chain []*x509.Certificate) ([]byte, error) {
	var pemBuffer bytes.Buffer

	if privateKey != nil {
		keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}

		keyBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		}

		if err := pem.Encode(&pemBuffer, keyBlock); err != nil {
			return nil, fmt.Errorf("failed to write private key PEM: %w", err)
		}
	}

	if leafCert != nil {
		leafBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: leafCert.Raw,
		}

		if err := pem.Encode(&pemBuffer, leafBlock); err != nil {
			return nil, fmt.Errorf("failed to write leaf certificate PEM: %w", err)
		}
	}

	for _, caCert := range chain {
		caBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCert.Raw,
		}

		if err := pem.Encode(&pemBuffer, caBlock); err != nil {
			return nil, fmt.Errorf("failed to write CA certificate PEM: %w", err)
		}
	}

	return pemBuffer.Bytes(), nil
}
