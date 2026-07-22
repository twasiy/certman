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
package exp

import (
	"certman/app/cmd/cert/exp/bundle"
	"certman/app/cmd/cert/exp/chain"
)

type ExportCmd struct {
	Leaf   LeafCmd          `cmd:"" help:"Export a standalone certificate to PEM or DER format."`
	Chain  chain.ChainCmd   `cmd:"" help:"Export a full certificate chain to PEM or PKCS#7 format."`
	Bundle bundle.BundleCmd `cmd:"" help:"Export a certificate and private key bundle to PKCS#12 or PEM format."`
}
