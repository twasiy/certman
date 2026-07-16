package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteCert(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "test_cert.crt")
	mockCertBytes := []byte("mock-cert-payload")

	err := WriteCert(targetFile, mockCertBytes)
	if err != nil {
		t.Fatalf("WriteCert failed unexpectedly: %v", err)
	}

	// Verify file contents
	data, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("Failed to read created cert file: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("Failed to decode PEM block from generated cert file")
	}

	if block.Type != "CERTIFICATE" {
		t.Errorf("Expected block type 'CERTIFICATE', got '%s'", block.Type)
	}

	if string(block.Bytes) != string(mockCertBytes) {
		t.Errorf("Expected bytes %s, got %s", mockCertBytes, block.Bytes)
	}
}

func TestWriteKey(t *testing.T) {
	// Generate valid keys for test cases
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key for testing: %v", err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key for testing: %v", err)
	}

	tmpDir := t.TempDir()

	tests := []struct {
		name          string
		filePath      string
		key           any
		keyType       KeyType
		usePKCS8      bool
		usePKIX       bool
		useCipher     bool
		expectedBlock string
		expectErr     bool
	}{
		{
			name:          "RSA Public Key - PKIX",
			filePath:      filepath.Join(tmpDir, "rsa_pub_pkix.pem"),
			key:           &rsaKey.PublicKey,
			keyType:       PUBLIC,
			usePKCS8:      false,
			usePKIX:       true,
			useCipher:     false,
			expectedBlock: "PUBLIC KEY",
			expectErr:     false,
		},
		{
			name:          "RSA Public Key - PKCS1",
			filePath:      filepath.Join(tmpDir, "rsa_pub_pkcs1.pem"),
			key:           &rsaKey.PublicKey,
			keyType:       PUBLIC,
			usePKCS8:      false,
			usePKIX:       false,
			useCipher:     false,
			expectedBlock: "RSA PUBLIC KEY",
			expectErr:     false,
		},
		{
			name:          "RSA Private Key - PKCS1",
			filePath:      filepath.Join(tmpDir, "rsa_priv_pkcs1.pem"),
			key:           rsaKey,
			keyType:       PRIVATE,
			usePKCS8:      false,
			usePKIX:       false,
			useCipher:     false,
			expectedBlock: "RSA PRIVATE KEY",
			expectErr:     false,
		},
		{
			name:          "RSA Private Key - PKCS8",
			filePath:      filepath.Join(tmpDir, "rsa_priv_pkcs8.pem"),
			key:           rsaKey,
			keyType:       PRIVATE,
			usePKCS8:      true,
			usePKIX:       false,
			useCipher:     false,
			expectedBlock: "PRIVATE KEY",
			expectErr:     false,
		},
		{
			name:          "ECDSA Private Key - Legacy EC",
			filePath:      filepath.Join(tmpDir, "ecdsa_priv.pem"),
			key:           ecdsaKey,
			keyType:       PRIVATE,
			usePKCS8:      false,
			usePKIX:       false,
			useCipher:     false,
			expectedBlock: "EC PRIVATE KEY",
			expectErr:     false,
		},
		{
			name:          "Invalid Public Key type for PKCS1 mapping",
			filePath:      filepath.Join(tmpDir, "invalid_pkcs1.pem"),
			key:           &ecdsaKey.PublicKey, // Will panic or fail because code casts key.(*rsa.PublicKey)
			keyType:       PUBLIC,
			usePKCS8:      false,
			usePKIX:       false,
			useCipher:     false,
			expectedBlock: "",
			expectErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// If a panic is expected (e.g., type assertion failure on ecdsaKey to *rsa.PublicKey)
			if tt.expectErr && tt.name == "Invalid Public Key type for PKCS1 mapping" {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("The code did not panic/error on invalid type assertion as expected")
					}
				}()
			}

			err := WriteKey(tt.filePath, tt.key, tt.keyType, tt.usePKCS8, tt.usePKIX, tt.useCipher)

			if (err != nil) != tt.expectErr {
				t.Fatalf("WriteKey() error = %v, expectErr %v", err, tt.expectErr)
			}

			if tt.expectErr {
				return
			}

			// Verify file generation and permissions
			info, err := os.Stat(tt.filePath)
			if err != nil {
				t.Fatalf("Failed to stat output file: %v", err)
			}

			// Validate file permissions matches logic (0644 for public, 0600 for private)
			expectedPerm := os.FileMode(0o600)
			if tt.keyType == PUBLIC {
				expectedPerm = os.FileMode(0o644)
			}
			if info.Mode().Perm() != expectedPerm {
				t.Errorf("Expected permissions %v, got %v", expectedPerm, info.Mode().Perm())
			}

			// Validate PEM block structure
			data, err := os.ReadFile(tt.filePath)
			if err != nil {
				t.Fatalf("Failed to read output file: %v", err)
			}

			block, _ := pem.Decode(data)
			if block == nil {
				t.Fatal("Failed to decode generated PEM block")
			}

			if block.Type != tt.expectedBlock {
				t.Errorf("Expected PEM block type %q, got %q", tt.expectedBlock, block.Type)
			}
		})
	}
}
