// Copyright 2026 Tassok Imam Wasiy

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
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
