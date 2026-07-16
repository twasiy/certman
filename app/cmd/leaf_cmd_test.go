package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"certman/app/utils"
)

// helper to write valid mock parent PEMs for the leaf test
func writeLeafParentPEMs(t *testing.T, tempDir string) (string, string) {
	t.Helper()

	// 1. Generate CA keys
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate parent key: %v", err)
	}

	// 2. Self-sign CA certificate
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "Mock Parent Issuing CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true, // Vital: parent must be a CA for domain.GetLeaf validation
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create self-signed CA cert: %v", err)
	}

	// 3. Write cert to file
	certPath := filepath.Join(tempDir, "parent_ca.crt")
	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("failed to write PEM cert: %v", err)
	}

	// 4. Write private key to file
	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	keyPath := filepath.Join(tempDir, "parent_ca.key")
	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer keyFile.Close()

	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("failed to write PEM key: %v", err)
	}

	return certPath, keyPath
}

func TestLeafCmd_Run(t *testing.T) {
	tempDir := t.TempDir()
	parentCertPath, parentKeyPath := writeLeafParentPEMs(t, tempDir)

	t.Run("Run Flag Mode - Valid Configuration", func(t *testing.T) {
		registry := &DataRegistry{}
		cmd := &LeafCmd{
			CommonName:        "api.example.com",
			Country:           []string{"US"},
			Organization:      []string{"Cloud Devs"},
			KeyType:           "ecdsa-256",
			TTL:               "8760h", // 1 year
			DNSNames:          []string{"api.example.com", "internal.example.com"},
			IPAddresses:       []string{"10.0.0.5"},
			ParentCertPath:    parentCertPath,
			ParentPrivkeyPath: parentKeyPath,
			IT:                false, // Disable interactive prompt
			KeyUsages:         []string{"digital-signature"},
			ExtKeyUsages:      []string{"server-auth", "client-auth"},
		}

		err := cmd.Run(registry)
		if err != nil {
			t.Fatalf("Expected Run() to succeed, got error: %v", err)
		}

		if registry.Certificate == nil {
			t.Fatal("Expected Leaf Certificate to be registered in DataRegistry")
		}
		if registry.PrivateKey == nil || registry.PublicKey == nil {
			t.Fatal("Expected Private and Public Key to be populated in DataRegistry")
		}

		// Verify properties of the created leaf certificate
		cert := registry.Certificate
		if cert.IsCA {
			t.Error("Leaf certificate must not have IsCA = true")
		}
		if cert.Subject.CommonName != "api.example.com" {
			t.Errorf("Expected CN 'api.example.com', got %q", cert.Subject.CommonName)
		}
		if len(cert.DNSNames) != 2 || cert.DNSNames[0] != "api.example.com" {
			t.Errorf("Expected SAN DNS names, got %v", cert.DNSNames)
		}
	})

	t.Run("Run Flag Mode - Missing Required Flags", func(t *testing.T) {
		tests := []struct {
			name    string
			setup   func(c *LeafCmd)
			wantErr string
		}{
			{
				name: "Missing Common Name",
				setup: func(c *LeafCmd) {
					c.CommonName = ""
				},
				wantErr: "missing required flag: --common-name",
			},
			{
				name: "Missing Key Type",
				setup: func(c *LeafCmd) {
					c.KeyType = ""
				},
				wantErr: "missing required flag: --key-type",
			},
			{
				name: "Missing Parent Cert Path",
				setup: func(c *LeafCmd) {
					c.ParentCertPath = ""
				},
				wantErr: "missing required flag: --parent-cert",
			},
			{
				name: "Missing Parent Key Path",
				setup: func(c *LeafCmd) {
					c.ParentPrivkeyPath = ""
				},
				wantErr: "missing required flag: --parent-priv-key",
			},
			{
				name: "Invalid TTL Unit",
				setup: func(c *LeafCmd) {
					c.TTL = "invalid-ttl"
				},
				wantErr: "invalid entry for --ttl",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				registry := &DataRegistry{}
				cmd := &LeafCmd{
					CommonName:        "valid-cn.com",
					KeyType:           "ed25519",
					TTL:               "24h",
					ParentCertPath:    parentCertPath,
					ParentPrivkeyPath: parentKeyPath,
					IT:                false,
				}

				tt.setup(cmd)
				err := cmd.Run(registry)
				if err == nil {
					t.Fatal("Expected Run() to return an error, but got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Expected error message containing %q, got: %v", tt.wantErr, err)
				}
			})
		}
	})

	t.Run("Run Flag Mode - Invalid IP SAN Parsing", func(t *testing.T) {
		registry := &DataRegistry{}
		cmd := &LeafCmd{
			CommonName:        "test-ip.com",
			KeyType:           "ed25519",
			TTL:               "12h",
			IPAddresses:       []string{"not-a-valid-ip"}, // Bad IP address format
			ParentCertPath:    parentCertPath,
			ParentPrivkeyPath: parentKeyPath,
			IT:                false,
		}

		// The Run method should execute, but ToNetIPs (called during Domain SAN assembly)
		// should skip the malformed IP, meaning the certificate is still created but
		// has an empty or unparsed IP list.
		err := cmd.Run(registry)
		if err != nil {
			t.Fatalf("Unexpected error: ToNetIPs should safely ignore or fail gracefully: %v", err)
		}
		if len(registry.Certificate.IPAddresses) != 0 {
			t.Errorf("Expected IP address parsing to skip the invalid string, but got parsed items: %v", registry.Certificate.IPAddresses)
		}
	})
}

func TestLeafPrompt_Validators(t *testing.T) {
	t.Run("Inline Common Name Validator Logic", func(t *testing.T) {
		validateCN := func(s string) error {
			if strings.TrimSpace(s) == "" {
				return func() error { return nil }() // Mock error representation matching target code blocks
			}
			return nil
		}

		if err := validateCN(strings.TrimSpace("  ")); err == nil {
			t.Error("Expected validation error for blank common name string, got nil")
		}
		if err := validateCN("valid.domain.com"); err != nil {
			t.Errorf("Expected valid domain to pass CN check, got error: %v", err)
		}
	})

	t.Run("TTL Validator Delegation", func(t *testing.T) {
		tests := []struct {
			input     string
			expectErr bool
		}{
			{"8760h", false},
			{"30d", false},
			{"2y", false},
			{"not-a-duration", true},
		}

		for _, tt := range tests {
			t.Run("TTL_"+tt.input, func(t *testing.T) {
				_, err := utils.ParseTTLToHours(tt.input)
				if (err != nil) != tt.expectErr {
					t.Errorf("Validation mismatch for %q: error = %v, expectErr %v", tt.input, err, tt.expectErr)
				}
			})
		}
	})
}
