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
package gen

type GenerateCmd struct {
	CA   CACmd   `cmd:"" help:"Generate a self-signed Root Certificate Authority (CA)."`
	ICA  ICACmd  `cmd:"" help:"Generate an Intermediate Certificate Authority (ICA) signed by a Root or parent CA."`
	Leaf LeafCmd `cmd:"" help:"Generate an end-entity (Leaf) certificate signed by an Intermediate or Root CA."`
}
