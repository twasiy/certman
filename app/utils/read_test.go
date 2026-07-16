package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Helper function to generate a self-signed cert for testing ReadCert
func generateTestCertBytes(t *testing.T) []byte {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate temp key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create test cert: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
}

func TestReadFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "testfile.txt")
	content := []byte("hello world")

	if err := os.WriteFile(filePath, content, 0o644); err != nil {
		t.Fatalf("failed to setup test file: %v", err)
	}

	tests := []struct {
		name      string
		path      string
		want      []byte
		expectErr bool
	}{
		{"Valid File Path", filePath, content, false},
		{"Non-existent File", filepath.Join(tempDir, "missing.txt"), nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadFile(tt.path)
			if (err != nil) != tt.expectErr {
				t.Fatalf("ReadFile() error = %v, expectErr %v", err, tt.expectErr)
			}
			if !tt.expectErr && string(got) != string(tt.want) {
				t.Errorf("ReadFile() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadCert(t *testing.T) {
	tempDir := t.TempDir()
	validCertPath := filepath.Join(tempDir, "valid_cert.pem")
	invalidCertPath := filepath.Join(tempDir, "invalid_cert.pem")
	nonPemPath := filepath.Join(tempDir, "non_pem.txt")

	// Write testing files
	_ = os.WriteFile(validCertPath, generateTestCertBytes(t), 0o644)
	_ = os.WriteFile(invalidCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage-bytes")}), 0o644)
	_ = os.WriteFile(nonPemPath, []byte("definitely not a pem block"), 0o644)

	tests := []struct {
		name      string
		path      string
		expectErr bool
	}{
		{"Valid Certificate PEM", validCertPath, false},
		{"Invalid Certificate Bytes", invalidCertPath, true},
		{"Non-PEM File Content", nonPemPath, true},
		{"Missing File", filepath.Join(tempDir, "missing.pem"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := ReadCert(tt.path)
			if (err != nil) != tt.expectErr {
				t.Fatalf("ReadCert() error = %v, expectErr %v", err, tt.expectErr)
			}
			if !tt.expectErr && cert == nil {
				t.Error("ReadCert() returned nil cert with no error")
			}
		})
	}
}

func TestReturnKeyAndReturnPrivateKey(t *testing.T) {
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Build exact raw byte variations
	pkcs1RsaBytes := x509.MarshalPKCS1PrivateKey(rsaPriv)
	pkcs1RsaPubBytes := x509.MarshalPKCS1PublicKey(&rsaPriv.PublicKey)

	pkcs8RsaBytes, _ := x509.MarshalPKCS8PrivateKey(rsaPriv)
	pkixRsaPubBytes, _ := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)

	ecBytes, _ := x509.MarshalECPrivateKey(ecPriv)

	t.Run("ReturnKey Matrix", func(t *testing.T) {
		tests := []struct {
			name      string
			bytes     []byte
			blockType string
			wantType  reflect.Type
			expectErr bool
		}{
			{"PKIX Public Key", pkixRsaPubBytes, "PUBLIC KEY", reflect.TypeFor[*rsa.PublicKey](), false},
			{"PKCS8 Private Key", pkcs8RsaBytes, "PRIVATE KEY", reflect.TypeFor[*rsa.PrivateKey](), false},
			{"PKCS1 RSA Private Key", pkcs1RsaBytes, "RSA PRIVATE KEY", reflect.TypeFor[*rsa.PrivateKey](), false},
			{"PKCS1 RSA Public Key", pkcs1RsaPubBytes, "RSA PUBLIC KEY", reflect.TypeFor[*rsa.PublicKey](), false},
			{"EC Private Key", ecBytes, "EC PRIVATE KEY", reflect.TypeFor[*ecdsa.PrivateKey](), false},
			{"Unsupported Block Type", ecBytes, "DUMMY PRIVATE KEY", nil, true},
			{"Invalid bytes for Type", pkcs1RsaBytes, "EC PRIVATE KEY", nil, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := ReturnKey(tt.bytes, tt.blockType)
				if (err != nil) != tt.expectErr {
					t.Fatalf("ReturnKey() error = %v, expectErr %v", err, tt.expectErr)
				}
				if !tt.expectErr {
					if got == nil {
						t.Fatal("ReturnKey() returned nil result unexpectedly")
					}
					if reflect.TypeOf(got) != tt.wantType {
						t.Errorf("ReturnKey() type = %v, want %v", reflect.TypeOf(got), tt.wantType)
					}
				}
			})
		}
	})

	t.Run("ReturnPrivateKey Auto-Detection", func(t *testing.T) {
		tests := []struct {
			name      string
			bytes     []byte
			wantType  reflect.Type
			expectErr bool
		}{
			{"PKCS8 Key Auto-Detect", pkcs8RsaBytes, reflect.TypeFor[*rsa.PrivateKey](), false},
			{"PKCS1 Key Auto-Detect", pkcs1RsaBytes, reflect.TypeFor[*rsa.PrivateKey](), false},
			{"EC Key Auto-Detect", ecBytes, reflect.TypeFor[*ecdsa.PrivateKey](), false},
			{"Invalid raw bytes", []byte("bad-key-payload"), nil, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := ReturnPrivateKey(tt.bytes)
				if (err != nil) != tt.expectErr {
					t.Fatalf("ReturnPrivateKey() error = %v, expectErr %v", err, tt.expectErr)
				}
				if !tt.expectErr && reflect.TypeOf(got) != tt.wantType {
					t.Errorf("ReturnPrivateKey() type = %v, want %v", reflect.TypeOf(got), tt.wantType)
				}
			})
		}
	})
}

func TestReadKeyAndReturnKeyWithBlockType(t *testing.T) {
	tempDir := t.TempDir()
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs1RsaBytes := x509.MarshalPKCS1PrivateKey(rsaPriv)

	keyPath := filepath.Join(tempDir, "rsa_private.pem")
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1RsaBytes}
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o644)

	t.Run("ReadKey Standard Flow", func(t *testing.T) {
		key, err := ReadKey(keyPath, false)
		if err != nil {
			t.Fatalf("ReadKey failed unexpectedly: %v", err)
		}
		if _, ok := key.(*rsa.PrivateKey); !ok {
			t.Errorf("Expected *rsa.PrivateKey, got %T", key)
		}
	})

	t.Run("ReturnKeyWithBlockType Standard Flow", func(t *testing.T) {
		key, blockType, err := ReturnKeyWithBlockType(keyPath, false)
		if err != nil {
			t.Fatalf("ReturnKeyWithBlockType failed: %v", err)
		}
		if blockType != "RSA PRIVATE KEY" {
			t.Errorf("Expected blockType 'RSA PRIVATE KEY', got %q", blockType)
		}
		if _, ok := key.(*rsa.PrivateKey); !ok {
			t.Errorf("Expected parsed key type *rsa.PrivateKey, got %T", key)
		}
	})
}
