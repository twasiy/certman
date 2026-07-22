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
package helper

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"pkit/app/utils"
	"pkit/db/base"
)

func GetCertificateChain(ctx context.Context, query base.Querier, current *x509.Certificate) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate

	workingCert := current
	const maxChainDepth = 10
	for depth := range maxChainDepth {
		if workingCert.Subject.String() == workingCert.Issuer.String() {
			if depth == 0 {
				return nil, fmt.Errorf("failed to build chain. Provided Certificate itself a Root CA Certificate")
			}
			break
		}

		if len(workingCert.AuthorityKeyId) == 0 {
			return nil, fmt.Errorf("failed to build chain. Chain ended early: %s lacks AKID", workingCert.Subject.CommonName)
		}

		akidHex := hex.EncodeToString(workingCert.AuthorityKeyId)
		parentDBCert, err := query.GetCertificateBySKID(ctx, akidHex)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch Certificate from DB: %w", err)
		}
		parentCert, err := utils.ParseCertificate([]byte(parentDBCert.CertificatePem))
		if err != nil {
			return nil, err
		}

		chain = append(chain, parentCert)
		workingCert = parentCert
	}

	return chain, nil
}
