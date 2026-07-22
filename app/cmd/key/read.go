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
	"encoding/pem"
	"errors"
	"fmt"
)

type ReadCmd struct {
	ID int `arg:"" help:"Database ID of the key pair to display."`
}

func (rc *ReadCmd) Run(ctx context.Context, query base.Querier) error {
	key, err := query.GetKeyByID(ctx, int64(rc.ID))
	if err != nil {
		return fmt.Errorf("failed to fetch key from DB: %w", err)
	}

	fmt.Printf("\u2022 Name: %s\n", key.Name)
	fmt.Printf("\u2022 Algorithm: %s\n", key.Algorithm)

	masterKey, err := utils.GetMasterKey()
	if err != nil {
		return fmt.Errorf("failed to fetch master key from your OS keyring: %w", err)
	}
	privKey, _ := pem.Decode([]byte(key.PrivateKeyPem))
	if privKey == nil {
		return errors.New("failed to decode private key")
	}
	decryptedPrivateKey, err := utils.Decrypt(privKey.Bytes, masterKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt private key: %w", err)
	}

	privateKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: decryptedPrivateKey,
	})
	if privateKeyPem == nil {
		return errors.New("failed to encode private key")
	}

	fmt.Printf("\n%s\n", string(privateKeyPem))
	fmt.Printf("\n%s\n", string(key.PublicKeyPem))

	return nil
}
