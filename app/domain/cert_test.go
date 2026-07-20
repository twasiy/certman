package domain

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestGetBaseTemplate(t *testing.T) {
	subject := pkix.Name{CommonName: "Test Base"}
	serial := big.NewInt(12345)
	ttl := 10

	tests := []struct {
		name string
		isCA bool
	}{
		{"CA Template", true},
		{"Non-CA Template", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := GetBaseTemplate(subject, serial, ttl, tt.isCA)
			if cert == nil {
				t.Fatal("Expected non-nil base template")
			}
			if cert.SerialNumber.Cmp(serial) != 0 {
				t.Errorf("Expected serial %v, got %v", serial, cert.SerialNumber)
			}
			if cert.Subject.CommonName != "Test Base" {
				t.Errorf("Expected CN 'Test Base', got %q", cert.Subject.CommonName)
			}
			if cert.IsCA != tt.isCA {
				t.Errorf("Expected IsCA = %v, got %v", tt.isCA, cert.IsCA)
			}
			if !cert.BasicConstraintsValid {
				t.Error("Expected BasicConstraintsValid to be true")
			}

			// Verify TTL allocation (approximate to avoid test race conditions)
			duration := cert.NotAfter.Sub(cert.NotBefore)
			expectedDuration := time.Duration(ttl) * time.Hour
			if duration < expectedDuration-time.Second || duration > expectedDuration+time.Second {
				t.Errorf("Expected duration close to %v, got %v", expectedDuration, duration)
			}
		})
	}
}

func TestGetCA(t *testing.T) {
	// Generate KeyPair for the Root CA
	caKeys, err := GetKey(ECDSA_P256)
	if err != nil {
		t.Fatalf("Failed to generate test keys: %v", err)
	}

	subject := pkix.Name{CommonName: "Root Root CA"}

	tests := []struct {
		name           string
		usages         *KeyUsageConfig
		expectedUsages x509.KeyUsage
		expectErr      bool
	}{
		{
			name:           "Default CA Usages",
			usages:         nil,
			expectedUsages: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			expectErr:      false,
		},
		{
			name: "Custom CA Usages",
			usages: &KeyUsageConfig{
				KeyUsages: []x509.KeyUsage{x509.KeyUsageCertSign, x509.KeyUsageDigitalSignature},
			},
			expectedUsages: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			expectErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caCert, err := GetCA(subject, 24, caKeys, tt.usages)
			if (err != nil) != tt.expectErr {
				t.Fatalf("GetCA() error = %v, expectErr %v", err, tt.expectErr)
			}
			if tt.expectErr {
				return
			}

			if !caCert.IsCA {
				t.Error("Expected certificate to have IsCA = true")
			}
			if caCert.KeyUsage != tt.expectedUsages {
				t.Errorf("Expected KeyUsage flags %v, got %v", tt.expectedUsages, caCert.KeyUsage)
			}

			// Validate self-signed logic (SKID equals AKID)
			if string(caCert.SubjectKeyId) != string(caCert.AuthorityKeyId) {
				t.Error("Subject Key ID and Authority Key ID must match on a self-signed root certificate")
			}

			// Verify signatures mathematically
			if err := caCert.CheckSignatureFrom(caCert); err != nil {
				t.Errorf("Self-signed certificate signature check failed: %v", err)
			}
		})
	}
}

func TestGetIntermediateAndLeaf(t *testing.T) {
	// Setup Root CA Certificate structure
	caKeys, _ := GetKey(ECDSA_P256)
	caCert, err := GetCA(pkix.Name{CommonName: "Root CA"}, 24, caKeys, nil)
	if err != nil {
		t.Fatalf("Failed to create parent CA: %v", err)
	}
	parentCA := &Certificate{Cert: caCert, Keys: caKeys}

	// Setup non-CA/leaf node structure to test verification failure
	leafKeys, _ := GetKey(RSA_2048)
	leafTemplate := GetBaseTemplate(pkix.Name{CommonName: "Not A CA"}, big.NewInt(1), 1, false)
	dummyLeafBytes, _ := x509.CreateCertificate(nil, leafTemplate, caCert, leafKeys.PublicKey, caKeys.PrivateKey)
	dummyLeafCert, _ := x509.ParseCertificate(dummyLeafBytes)
	invalidParent := &Certificate{Cert: dummyLeafCert, Keys: leafKeys}

	// Key Pairs for Intermediate and Leaf certificates
	interKeys, _ := GetKey(ECDSA_P256)
	targetLeafKeys, _ := GetKey(RSA_2048)

	// Mock SANs structure
	parsedURI, _ := url.Parse("https://example.com/api")
	testSANs := SANs{
		DNSNames:       []string{"example.com", "www.example.com"},
		EmailAddresses: []string{"admin@example.com"},
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
		URIs:           []*url.URL{parsedURI},
	}

	t.Run("GetIntermediate Hierarchy Verification", func(t *testing.T) {
		tests := []struct {
			name      string
			parent    *Certificate
			expectErr bool
		}{
			{"Valid Parent CA", parentCA, false},
			{"Invalid Non-CA Parent", invalidParent, true},
			{"Nil Parent Structure", nil, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				interCert, err := GetICA(
					pkix.Name{CommonName: "Intermediate CA"},
					testSANs,
					12,
					interKeys,
					tt.parent,
					nil,
				)

				if (err != nil) != tt.expectErr {
					t.Fatalf("GetIntermediate() error = %v, expectErr %v", err, tt.expectErr)
				}
				if tt.expectErr {
					return
				}

				if !interCert.IsCA {
					t.Error("Intermediate must be a CA")
				}
				if interCert.MaxPathLen != 0 || !interCert.MaxPathLenZero {
					t.Error("Expected MaxPathLen = 0 (restrictive chain limit constraints)")
				}

				// Check signature chain
				if err := interCert.CheckSignatureFrom(parentCA.Cert); err != nil {
					t.Errorf("Intermediate signature not verified by Root: %v", err)
				}

				// Verify SAN mapping
				if len(interCert.DNSNames) != 2 || interCert.DNSNames[0] != "example.com" {
					t.Errorf("SAN mapping failed on intermediate creation: %v", interCert.DNSNames)
				}
			})
		}
	})

	t.Run("GetLeaf Issuance and Verification", func(t *testing.T) {
		tests := []struct {
			name      string
			parent    *Certificate
			expectErr bool
		}{
			{"Valid CA Parent", parentCA, false},
			{"Invalid Non-CA Parent", invalidParent, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				leafCert, err := GetLeaf(
					pkix.Name{CommonName: "Leaf Certificate"},
					testSANs,
					6,
					targetLeafKeys,
					tt.parent,
					nil,
				)

				if (err != nil) != tt.expectErr {
					t.Fatalf("GetLeaf() error = %v, expectErr %v", err, tt.expectErr)
				}
				if tt.expectErr {
					return
				}

				if leafCert.IsCA {
					t.Error("Leaf certificate must not be a CA")
				}

				// Verify Default Leaf usages (digital signature & key encipherment)
				expectedUsages := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
				if leafCert.KeyUsage != expectedUsages {
					t.Errorf("Expected Leaf KeyUsage %v, got %v", expectedUsages, leafCert.KeyUsage)
				}

				// Verify certificate chain signature
				if err := leafCert.CheckSignatureFrom(parentCA.Cert); err != nil {
					t.Errorf("Leaf signature not verified by parent CA: %v", err)
				}
			})
		}
	})
}
