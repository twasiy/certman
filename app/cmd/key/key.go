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

type KeyCmd struct {
	List    ListCmd    `cmd:"" help:"List cryptographic key pairs stored in the database."`
	Read    ReadCmd    `cmd:"" help:"Display the raw PEM encoded data of a key pair."`
	Verify  VerifyCmd  `cmd:"" help:"Verify the cryptographic integrity and match of a key pair against a certificate."`
	Inspect InspectCmd `cmd:"" help:"Inspect detailed technical specifications and mathematical validity of a key pair."`
	Export  ExportCmd  `cmd:"" help:"Export key pairs to PEM, DER, or encrypted binary blob files."`
}
