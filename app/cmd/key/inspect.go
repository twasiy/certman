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
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

type InspectCmd struct {
	ID       int  `arg:"" help:"Database ID of the key pair to inspect."`
	Validate bool `name:"validate" short:"v" help:"Verify the mathematical integrity and validity of the private key."`
}

func (ic *InspectCmd) Run(ctx context.Context, query base.Querier) error {
	key, err := query.GetKeyByID(ctx, int64(ic.ID))
	if err != nil {
		return fmt.Errorf("failed to fetch key from DB: %w", err)
	}

	privateKey, publicKey, err := utils.ParseKeys([]byte(key.PrivateKeyPem), []byte(key.PublicKeyPem))
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintf(w, "Key Inspection Report — %s\n", key.Name)
	fmt.Fprintln(w, strings.Repeat("─", 60))

	ic.inspectPrivateKey(w, privateKey, ic.Validate)

	fmt.Fprintln(w, strings.Repeat("─", 60))

	ic.inspectPublicKey(w, publicKey, ic.Validate)

	fmt.Fprintln(w, strings.Repeat("─", 60))

	return w.Flush()
}

func (ic *InspectCmd) inspectPrivateKey(w *tabwriter.Writer, key any, validate bool) {
	fmt.Fprintln(w, "[ PRIVATE KEY ]")
	switch k := key.(type) {
	case *rsa.PrivateKey:
		fmt.Fprintln(w, "  Algorithm:\tRSA")
		fmt.Fprintf(w, "  Modulus Size:\t%d-bit\n", k.Size()*8)
		fmt.Fprintf(w, "  Public Exponent (e):\t%d (0x%x)\n", k.E, k.E)
		fmt.Fprintf(w, "  Modulus Fingerprint:\t%s...\n", utils.TruncateHex(k.N.Bytes()))
		fmt.Fprintf(w, "  Prime P Size:\t%d bits\n", len(k.Primes[0].Bytes())*8)
		fmt.Fprintf(w, "  Prime Q Size:\t%d bits\n", len(k.Primes[1].Bytes())*8)
		if validate {
			if err := k.Validate(); err != nil {
				fmt.Fprintf(w, "  Validation Failed:\t%s\n", err)
			} else {
				fmt.Fprintln(w, "  Validation Status:\tMathematically sound")
			}
		}

	case *ecdsa.PrivateKey:
		fmt.Fprintln(w, "  Algorithm:\tECDSA")
		fmt.Fprintf(w, "  Curve:\t%s\n", k.Params().Name)
		fmt.Fprintf(w, "  Order (N):\t%s...\n", utils.TruncateHex(k.Params().N.Bytes()))
		fmt.Fprintln(w, "  Private Scalar (D):\t[hidden]")
		if validate {
			if _, err := k.ECDH(); err == nil {
				fmt.Fprintln(w, "  Validation Status:\tCurve point valid")
			} else {
				fmt.Fprintf(w, "  Validation Failed:\t%s\n", err)
			}
		}

	case ed25519.PrivateKey:
		fmt.Fprintln(w, "  Algorithm:\tEd25519")
		fmt.Fprintf(w, "  Seed:\t%s...\n", utils.TruncateHex(k.Seed()))
		fmt.Fprintf(w, "  Public Key (derived):\t%s\n", hex.EncodeToString(k.Public().(ed25519.PublicKey)))

	default:
		fmt.Fprintf(w, "  Unknown type:\t%T\n", k)
	}
}

func (ic *InspectCmd) inspectPublicKey(w *tabwriter.Writer, key any, validate bool) {
	fmt.Fprintln(w, "[ PUBLIC KEY ]")
	switch k := key.(type) {
	case *rsa.PublicKey:
		fmt.Fprintln(w, "  Algorithm:\tRSA")
		fmt.Fprintf(w, "  Modulus Size:\t%d-bit\n", k.Size()*8)
		fmt.Fprintf(w, "  Public Exponent (e):\t%d (0x%x)\n", k.E, k.E)
		fmt.Fprintf(w, "  Modulus Fingerprint:\t%s...\n", utils.TruncateHex(k.N.Bytes()))

	case *ecdsa.PublicKey:
		fmt.Fprintln(w, "  Algorithm:\tECDSA")
		fmt.Fprintf(w, "  Curve:\t%s\n", k.Params().Name)
		if pubBytes, err := k.Bytes(); err == nil {
			fmt.Fprintf(w, "  Uncompressed Point:\t%s...\n", utils.TruncateHex(pubBytes))
		}
		if validate {
			if _, err := k.ECDH(); err == nil {
				fmt.Fprintln(w, "  Validation Status:\tCurve point valid")
			} else {
				fmt.Fprintf(w, "  Validation Failed:\t%s\n", err)
			}
		}

	case ed25519.PublicKey:
		fmt.Fprintln(w, "  Algorithm:\tEd25519")
		fmt.Fprintf(w, "  Public Point:\t%s\n", hex.EncodeToString(k))
		if validate {
			fmt.Fprintln(w, "  Validation Status:\tEd25519 public keys are always valid by construction")
		}

	default:
		fmt.Fprintf(w, "  Unknown type:\t%T\n", k)
	}
}
