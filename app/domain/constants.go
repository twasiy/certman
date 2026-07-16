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
