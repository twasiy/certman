package chain

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"go.mozilla.org/pkcs7"
)

// GetPKCS7Chain encodes the leaf certificate and CA chain into a Degenerate PKCS#7 (.p7b) structure.
func GetPKCS7Chain(leafCert *x509.Certificate, caChain []*x509.Certificate) ([]byte, error) {
	var rawCertBytes []byte

	if leafCert != nil {
		rawCertBytes = append(rawCertBytes, leafCert.Raw...)
	}

	for _, caCert := range caChain {
		rawCertBytes = append(rawCertBytes, caCert.Raw...)
	}

	p7Data, err := pkcs7.DegenerateCertificate(rawCertBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encode PKCS#7 certificate chain: %w", err)
	}

	p7PemBlock := &pem.Block{
		Type:  "PKCS7",
		Bytes: p7Data,
	}

	return pem.EncodeToMemory(p7PemBlock), nil
}
