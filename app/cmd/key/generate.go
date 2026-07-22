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
	"context"
	"fmt"
	"pkit/app/domain"
	"pkit/app/utils"
	"pkit/db/base"
)

type GenerateCmd struct {
	KeyType string `name:"type" required:"" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ed25519" help:"Cryptographic algorithm and key size to generate."`
	Name    string `name:"name" required:"" help:"Friendly identifier name for the key pair in the database."`
}

func (gc *GenerateCmd) Run(ctx context.Context, query base.Querier) error {
	keyPair, err := domain.GetKey(domain.KeyType(gc.KeyType))
	if err != nil {
		return err
	}

	privBlobPem, pubPem, err := utils.ReturnPrivPubPem(keyPair.PrivateKey, keyPair.PublicKey)
	if err != nil {
		return err
	}

	_, err = query.CreateKeyPair(ctx, base.CreateKeyPairParams{
		Name:          gc.Name,
		Algorithm:     gc.KeyType,
		PrivateKeyPem: privBlobPem,
		PublicKeyPem:  pubPem,
	})
	if err != nil {
		return fmt.Errorf("failed to create Key Pair in DB: %w", err)
	}

	return nil
}
