package helper

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
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
