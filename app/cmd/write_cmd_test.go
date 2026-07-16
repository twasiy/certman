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
	"testing"
	"time"
)

// Helper function to generate a mock in-memory X.509 Certificate and Private Key.
func generateMockCert(t *testing.T, cn string, issuerCN string, isCA bool) (*x509.Certificate, any, any) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate mock key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: issuerCN},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		IsCA:         isCA,
	}

	rawBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to sign mock cert: %v", err)
	}

	parsed, err := x509.ParseCertificate(rawBytes)
	if err != nil {
		t.Fatalf("Failed to parse mock cert: %v", err)
	}

	return parsed, privKey, &privKey.PublicKey
}

func TestWriteCmd_Run(t *testing.T) {
	t.Run("Write Root CA - Success", func(t *testing.T) {
		// Mock DataRegistry containing a self-signed Root CA cert
		cert, privKey, pubKey := generateMockCert(t, "My Root CA", "My Root CA", true)
		registry := &DataRegistry{
			Certificate: cert,
			PrivateKey:  privKey,
			PublicKey:   pubKey,
		}

		cmd := &WriteCmd{
			Force:   true,
			Encrypt: false,
		}

		// Run the writer
		err := cmd.Run(registry)
		if err != nil {
			t.Fatalf("Expected Run() to succeed on Root CA writing: %v", err)
		}

		// Compute expected output directory (determined by ~/certman/certificates/roots/[snake_case_cn])
		// Since our path resolver utilizes home-directory joins internally, we confirm execution
		// succeeded without hitting OS-level file permission crashes.
	})

	t.Run("Write Leaf with Fullchain Bundle Generation", func(t *testing.T) {
		tempDir := t.TempDir()

		// Write a dummy Parent PEM file to our temporary test directory
		parentCertPath := filepath.Join(tempDir, "issuing_parent.crt")
		parentCert, _, _ := generateMockCert(t, "Issuing Intermediate CA", "Issuing Intermediate CA", true)
		parentPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: parentCert.Raw})

		err := os.WriteFile(parentCertPath, parentPEM, 0o600)
		if err != nil {
			t.Fatalf("Failed setup of test parent certificate on disk: %v", err)
		}

		// Define a mock leaf certificate signed by the intermediate
		leafCert, leafPrivKey, leafPubKey := generateMockCert(t, "service.internal", "Issuing Intermediate CA", false)
		registry := &DataRegistry{
			Certificate: leafCert,
			PrivateKey:  leafPrivKey,
			PublicKey:   leafPubKey,
		}

		// Build Command with Leaf values targeting the temp path
		cmd := &WriteCmd{
			Leaf: LeafCmd{
				ParentCertPath: parentCertPath,
			},
			Force:   true,
			Encrypt: false,
		}

		err = cmd.Run(registry)
		if err != nil {
			t.Fatalf("Expected Run() to succeed on leaf writing: %v", err)
		}
	})

	t.Run("Force Overwrite Check", func(t *testing.T) {
		cert, privKey, pubKey := generateMockCert(t, "Duplicate Cert", "Duplicate Cert", true)
		registry := &DataRegistry{
			Certificate: cert,
			PrivateKey:  privKey,
			PublicKey:   pubKey,
		}

		// First pass: Write output assets
		cmdFirstRun := &WriteCmd{Force: true}
		err := cmdFirstRun.Run(registry)
		if err != nil {
			t.Fatalf("First run write execution failed unexpectedly: %v", err)
		}

		// Second pass: Attempting write without --force should error out cleanly
		cmdNoForce := &WriteCmd{Force: false}
		err = cmdNoForce.Run(registry)
		if err == nil {
			t.Fatal("Expected second run to fail without force overwrite flag, but succeeded")
		}
	})
}
