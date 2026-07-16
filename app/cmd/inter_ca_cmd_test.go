package cmd

import (
	"certman/app/utils"
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
)

// helper to write temporary certificate and key PEM files for tests
func writeTestPEMs(t *testing.T, tempDir string) (string, string) {
	t.Helper()

	// 1. Generate parent key pair (ECDSA P256)
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate parent ecdsa key: %v", err)
	}

	// 2. Self-sign a parent certificate template
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Parent Mock Root CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create self-signed parent cert: %v", err)
	}

	// 3. Write Cert PEM
	certPath := filepath.Join(tempDir, "parent_ca.crt")
	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}
	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		t.Fatalf("failed to write PEM cert: %v", err)
	}

	// 4. Write Private Key PEM
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

	err = pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		t.Fatalf("failed to write PEM key: %v", err)
	}

	return certPath, keyPath
}

func TestInterCACmd_Run(t *testing.T) {
	tempDir := t.TempDir()
	parentCertPath, parentKeyPath := writeTestPEMs(t, tempDir)

	t.Run("Run Flag Mode - Valid Configuration", func(t *testing.T) {
		registry := &DataRegistry{}
		cmd := &InterCACmd{
			CommonName:        "Corporate Intermediate CA 1A",
			Country:           []string{"US"},
			Organization:      []string{"Acme Corp"},
			KeyType:           "ecdsa-256",
			TTL:               "720h", // 30 days
			DNSNames:          []string{"int.example.com"},
			EmailAddresses:    []string{"ca-admin@example.com"},
			ParentCertPath:    parentCertPath,
			ParentPrivkeyPath: parentKeyPath,
			IT:                false, // Bypass terminal interaction
			KeyUsages:         []string{"cert-sign", "crl-sign"},
			ExtKeyUsages:      []string{"server-auth"},
		}

		err := cmd.Run(registry)
		if err != nil {
			t.Fatalf("Expected Run() to succeed, got error: %v", err)
		}

		if registry.Certificate == nil {
			t.Fatal("Expected Intermediate Certificate to be registered in DataRegistry")
		}
		if registry.PrivateKey == nil || registry.PublicKey == nil {
			t.Fatal("Expected Private and Public Key to be generated and registered")
		}

		// Inspect values applied to the generated intermediate certificate
		cert := registry.Certificate
		if cert.Subject.CommonName != "Corporate Intermediate CA 1A" {
			t.Errorf("Expected CN 'Corporate Intermediate CA 1A', got %q", cert.Subject.CommonName)
		}
		if !cert.IsCA {
			t.Error("Expected generated intermediate certificate to have IsCA = true")
		}
		if len(cert.DNSNames) == 0 || cert.DNSNames[0] != "int.example.com" {
			t.Errorf("Expected SAN DNS 'int.example.com', got %v", cert.DNSNames)
		}
	})

	t.Run("Run Flag Mode - Missing Required Flags", func(t *testing.T) {
		tests := []struct {
			name    string
			setup   func(c *InterCACmd)
			wantErr string
		}{
			{
				name: "Missing Common Name",
				setup: func(c *InterCACmd) {
					c.CommonName = ""
				},
				wantErr: "missing required flag: --common-name",
			},
			{
				name: "Missing Key Type",
				setup: func(c *InterCACmd) {
					c.KeyType = ""
				},
				wantErr: "missing required flag: --key-type",
			},
			{
				name: "Missing Parent Cert",
				setup: func(c *InterCACmd) {
					c.ParentCertPath = ""
				},
				wantErr: "missing required flag: --parent-cert",
			},
			{
				name: "Missing Parent Private Key",
				setup: func(c *InterCACmd) {
					c.ParentPrivkeyPath = ""
				},
				wantErr: "missing required flag: --parent-priv-key",
			},
			{
				name: "Invalid TTL format",
				setup: func(c *InterCACmd) {
					c.TTL = "invalid-ttl"
				},
				wantErr: "invalid entry for --ttl",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				registry := &DataRegistry{}
				cmd := &InterCACmd{
					CommonName:        "Test Inter",
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
					t.Errorf("Expected error containing %q, got: %v", tt.wantErr, err)
				}
			})
		}
	})

	t.Run("Run Flag Mode - Corrupt/Invalid Key Paths", func(t *testing.T) {
		registry := &DataRegistry{}
		cmd := &InterCACmd{
			CommonName:        "Corrupt Paths",
			KeyType:           "ed25519",
			TTL:               "24h",
			ParentCertPath:    "/non/existent/path/cert.crt",
			ParentPrivkeyPath: parentKeyPath,
			IT:                false,
		}

		err := cmd.Run(registry)
		if err == nil {
			t.Fatal("Expected Run() to fail due to a non-existent certificate file path")
		}
	})
}

func TestInterCAPrompt_ValidationDelegation(t *testing.T) {
	// Reusable test for the inline value validations defined within InterCAPrompt
	t.Run("TTL Validator Delegate", func(t *testing.T) {
		tests := []struct {
			input     string
			expectErr bool
		}{
			{"10y", false},
			{"30d", false},
			{"720h", false},
			{"corrupt-format", true},
		}

		for _, tt := range tests {
			t.Run("TTL_"+tt.input, func(t *testing.T) {
				_, err := utils.ParseTTLToHours(tt.input)
				if (err != nil) != tt.expectErr {
					t.Errorf("Validation mismatch for input %q: error = %v, expectErr %v", tt.input, err, tt.expectErr)
				}
			})
		}
	})
}
