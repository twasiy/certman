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
package csr

type CSRCmd struct {
	Generate  GenerateCmd `cmd:"" help:"Generate a new Certificate Signing Request (CSR)."`
	List      ListCmd     `cmd:"" help:"List Certificate Signing Requests (CSRs) stored in the database."`
	Read      ReadCmd     `cmd:"" help:"Display the raw PEM encoded data of a CSR."`
	Inspect   InspectCmd  `cmd:"" help:"Inspect detailed properties and requested attributes of a CSR."`
	VerifyCmd VerifyCmd   `cmd:"" help:"Verify the self-signature and key integrity of a CSR."`
	Sign      SignCmd     `cmd:"" help:"Sign a pending CSR using an issuer certificate to produce an X.509 certificate."`
	Export    ExportCmd   `cmd:"" help:"Export a CSR to PEM or DER format files."`
}
