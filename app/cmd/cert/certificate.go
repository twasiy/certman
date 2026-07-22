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
package cert

import (
	"certman/app/cmd/cert/exp"
	"certman/app/cmd/cert/gen"
)

type CertCmd struct {
	Generate gen.GenerateCmd `cmd:"" help:"Generate a new Root CA, Intermediate CA, or Leaf certificate."`
	List     ListCmd         `cmd:"" help:"List certificates stored in the database."`
	Read     ReadCmd         `cmd:"" help:"Display the raw PEM encoded data of a certificate."`
	Inspect  InspectCmd      `cmd:"" help:"Inspect detailed properties, extensions, and metadata of a certificate."`
	Validate ValidateCmd     `cmd:"" help:"Perform sanity and structural policy checks on a certificate."`
	Verify   VerifyCmd       `cmd:"" help:"Verify the cryptographic signature and chain trust of a certificate."`
	Diff     DiffCmd         `cmd:"" help:"Compare two certificates and highlight structural differences."`
	Revoke   RevokeCmd       `cmd:"" help:"Revoke an active certificate with a specified reason code."`
	Rotate   RotateCmd       `cmd:"" help:"Rotate an existing certificate with a newly generated key pair."`
	Export   exp.ExportCmd   `cmd:"" help:"Export certificates, full chains, or PKCS#12 bundles."`
}
