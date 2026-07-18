package archive

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Helper to capture standard output printed by the command execution
func captureInspectStdout(t *testing.T, runFunc func() error) (string, error) {
	t.Helper()
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runFunc()

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String(), err
}

// Generates a valid test certificate on disk and returns its path along with original DER bytes
func createTestCertFile(t *testing.T, tempDir string, cn string) (string, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test-Org"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC),
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to sign mock cert: %v", err)
	}

	filePath := filepath.Join(tempDir, "test_inspect.cert")
	file, err := os.Create(filePath)
	if err != nil {
		t.Fatalf("Failed to create mock cert file: %v", err)
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		t.Fatalf("Failed to encode certificate: %v", err)
	}

	return filePath, derBytes
}

// Writes a cryptographic key of a specified algorithm to a PEM file
func writeKeyFile(t *testing.T, tempDir, filename, blockType string, keyBytes []byte) string {
	t.Helper()
	path := filepath.Join(tempDir, filename)
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{Type: blockType, Bytes: keyBytes})
	if err != nil {
		t.Fatalf("Failed to encode key PEM block: %v", err)
	}
	return path
}

func TestInspectCertCmd_Run(t *testing.T) {
	tempDir := t.TempDir()
	certPath, _ := createTestCertFile(t, tempDir, "inspect.test.com")

	t.Run("Inspect Certificate - Standard Pretty Output", func(t *testing.T) {
		cmd := &InspectCertCmd{
			Path:        certPath,
			Fingerprint: true,
			Extensions:  true,
			JSON:        false,
		}

		output, err := captureInspectStdout(t, func() error {
			return cmd.Run()
		})

		if err != nil {
			t.Fatalf("Expected Run to succeed, got error: %v", err)
		}

		// Validate containing key properties
		assertions := []string{
			"Certificate Inspection Report",
			"Common Name (CN): inspect.test.com",
			"Organization (O): Test-Org",
			"Country (C)     : US",
			"Serial Number: 3039", // Hex representation of 12345 is 3039
			"Active From  : 2026-01-01 12:00:00 UTC",
			"Expires On   : 2027-01-01 12:00:00 UTC",
			"SHA-256:",
			"Basic Constraints (CA): true",
			"Digital Signature, Certificate Signing",
		}

		for _, phrase := range assertions {
			if !strings.Contains(output, phrase) {
				t.Errorf("Pretty-print output missing expected term %q. Got:\n%s", phrase, output)
			}
		}
	})

	t.Run("Inspect Certificate - Structured JSON Output", func(t *testing.T) {
		cmd := &InspectCertCmd{
			Path:        certPath,
			Fingerprint: true,
			JSON:        true,
		}

		output, err := captureInspectStdout(t, func() error {
			return cmd.Run()
		})

		if err != nil {
			t.Fatalf("Expected Run to succeed in JSON mode, got: %v", err)
		}

		var parsed certJSONOutput
		err = json.Unmarshal([]byte(output), &parsed)
		if err != nil {
			t.Fatalf("Expected valid JSON output, failed to parse: %v\nOutput: %s", err, output)
		}

		if parsed.SerialNumber != "3039" {
			t.Errorf("Expected SerialNumber '3039', got %q", parsed.SerialNumber)
		}
		if parsed.NotBefore != "2026-01-01 12:00:00 UTC" {
			t.Errorf("Expected NotBefore date format mismatch, got %q", parsed.NotBefore)
		}
		if parsed.SHA256 == "" {
			t.Error("Expected SHA256 fingerprint entry in JSON payload, but was empty")
		}
	})
}

func TestInspectKeyCmd_Run(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Generate an RSA Key Pair
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaPrivBytes := x509.MarshalPKCS1PrivateKey(rsaPriv)
	rsaKeyPath := writeKeyFile(t, tempDir, "rsa.key", "RSA PRIVATE KEY", rsaPrivBytes)

	// 2. Generate an ECDSA Key Pair
	ecdsaPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaPrivBytes, _ := x509.MarshalECPrivateKey(ecdsaPriv)
	ecdsaKeyPath := writeKeyFile(t, tempDir, "ecdsa.key", "EC PRIVATE KEY", ecdsaPrivBytes)

	// 3. Generate an Ed25519 Key Pair
	_, ed25519Priv, _ := ed25519.GenerateKey(rand.Reader)
	ed25519PrivBytes, _ := x509.MarshalPKCS8PrivateKey(ed25519Priv)
	ed25519KeyPath := writeKeyFile(t, tempDir, "ed25519.key", "PRIVATE KEY", ed25519PrivBytes)

	tests := []struct {
		name       string
		path       string
		validate   bool
		assertions []string
	}{
		{
			name:     "Inspect RSA Private Key",
			path:     rsaKeyPath,
			validate: true,
			assertions: []string{
				"Key Inspection Report",
				"PEM Block Header Type: RSA PRIVATE KEY",
				"Cipher Suite          : RSA",
				"Modulus Bit Size     : 2048-bit",
				"Validation Status     :  Mathematical Integrity Intact",
			},
		},
		{
			name:     "Inspect ECDSA Private Key",
			path:     ecdsaKeyPath,
			validate: true,
			assertions: []string{
				"PEM Block Header Type: EC PRIVATE KEY",
				"Cipher Suite          : ECDSA",
				"Chosen Curve Architecture: P-256",
				"Validation Status     :  Curve Point Verification Successful",
			},
		},
		{
			name:     "Inspect Ed25519 Private Key",
			path:     ed25519KeyPath,
			validate: false,
			assertions: []string{
				"PEM Block Header Type: PRIVATE KEY",
				"Cipher Suite          : Ed25519",
				"Parameters            : Twisted Edwards Curve, Curve25519 base",
				"Extracted Public Key",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &InspectKeyCmd{
				Path:     tt.path,
				Validate: tt.validate,
				Decrypt:  false,
			}

			output, err := captureInspectStdout(t, func() error {
				return cmd.Run()
			})

			if err != nil {
				t.Fatalf("Unexpected execution error: %v", err)
			}

			for _, phrase := range tt.assertions {
				if !strings.Contains(output, phrase) {
					t.Errorf("Missing assertion %q in output. Got:\n%s", phrase, output)
				}
			}
		})
	}
}

func TestFormatDN(t *testing.T) {
	t.Run("Empty Distinguished Name Formatter Fallback", func(t *testing.T) {
		dn := pkix.Name{}
		formatted := formatDN(dn)
		if formatted != "Empty Distinguished Name" {
			t.Errorf("Expected fallback string, got %q", formatted)
		}
	})

	t.Run("Full Complex DN Formatter Output", func(t *testing.T) {
		dn := pkix.Name{
			CommonName:   "server.local",
			Organization: []string{"Company Inc.", "Security Division"},
			Country:      []string{"US"},
			Province:     []string{"California"},
			Locality:     []string{"San Francisco"},
		}
		formatted := formatDN(dn)
		expected := "CN=server.local, O=Company Inc., Security Division, C=US, ST=California, L=San Francisco"
		if formatted != expected {
			t.Errorf("DN format mismatch.\nExpected: %q\nGot:      %q", expected, formatted)
		}
	})
}

func TestTruncateHex(t *testing.T) {
	t.Run("Handle empty byte slice", func(t *testing.T) {
		if res := truncateHex([]byte{}); res != "empty" {
			t.Errorf("Expected 'empty' string, got %q", res)
		}
	})

	t.Run("Perform truncation on long hex values", func(t *testing.T) {
		data, _ := hex.DecodeString("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
		res := truncateHex(data)
		if len(res) != 32 {
			t.Errorf("Expected truncated result of length 32, got %d chars: %q", len(res), res)
		}
	})
}
