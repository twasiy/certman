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

// GetICA generates an intermediate CA certificate with dynamic key usages.
func GetICA(subject pkix.Name, san SANs, ttlInHour int, keyPair *KeyPair, parent *Certificate, usages *KeyUsageConfig) (*x509.Certificate, error) {
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
