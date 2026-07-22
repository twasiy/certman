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
