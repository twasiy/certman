package chain

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// GetPEMChain combines the leaf certificate and CA chain into a single concatenated PEM byte slice.
func GetPEMChain(leafCert *x509.Certificate, caChain []*x509.Certificate) ([]byte, error) {
	var pemBuffer bytes.Buffer

	if leafCert != nil {
		leafBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: leafCert.Raw,
		}
		if err := pem.Encode(&pemBuffer, leafBlock); err != nil {
			return nil, fmt.Errorf("failed to encode leaf certificate to PEM: %w", err)
		}
	}

	for _, caCert := range caChain {
		caBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCert.Raw,
		}
		if err := pem.Encode(&pemBuffer, caBlock); err != nil {
			return nil, fmt.Errorf("failed to encode CA certificate to PEM: %w", err)
		}
	}

	return pemBuffer.Bytes(), nil
}
