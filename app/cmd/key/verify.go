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
package key

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
)

type VerifyCmd struct {
	ID int `arg:"" help:"Database ID of the key pair to verify against its certificate."`
}

func (vc *VerifyCmd) Run(ctx context.Context, query base.Querier) error {
	dbCert, err := query.GetCertificateByID(ctx, int64(vc.ID))
	if err != nil {
		return fmt.Errorf("failed to fetch Certificate from DB: %w", err)
	}
	cert, err := utils.ParseCertificate([]byte(dbCert.CertificatePem))
	if err != nil {
		return err
	}
	var keyName string

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
