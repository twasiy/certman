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
package crl

type CrlCmd struct {
	Generate GenerateCmd `cmd:"" help:"Generate a new Certificate Revocation List (CRL) for an issuer."`
	List     ListCmd     `cmd:"" help:"List Certificate Revocation Lists (CRLs) stored in the database."`
	Read     ReadCmd     `cmd:"" help:"Display the raw PEM encoded data of a CRL."`
	Verify   VerifyCmd   `cmd:"" help:"Verify the cryptographic signature of a CRL against its issuer."`
	Inspect  InspectCmd  `cmd:"" help:"Inspect detailed attributes and revoked entries of a CRL."`
	Diff     DiffCmd     `cmd:"" help:"Compare two CRLs and highlight revoked entry differences."`
	Validate ValidateCmd `cmd:"" help:"Perform sanity and validity period checks on a CRL."`
	Export   ExportCmd   `cmd:"" help:"Export a CRL to PEM or DER format files."`
}
