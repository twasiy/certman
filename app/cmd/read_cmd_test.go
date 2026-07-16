package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helper to capture stdout printed during command execution
func captureStdout(f func() error) (string, error) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := f()

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String(), err
}

func TestReadCertCmd_Run(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Write a dummy valid certificate file
	validCertPath := filepath.Join(tempDir, "test.cert")
	dummyCertContent := []byte("-----BEGIN CERTIFICATE-----\nMOCK_BASE64_DATA\n-----END CERTIFICATE-----\n")
	err := os.WriteFile(validCertPath, dummyCertContent, 0o600)
	if err != nil {
		t.Fatalf("failed to write test cert file: %v", err)
	}

	t.Run("Successfully read and print valid certificate", func(t *testing.T) {
		cmd := &ReadCertCmd{
			Path: validCertPath,
		}

		output, err := captureStdout(func() error {
			return cmd.Run()
		})

		if err != nil {
			t.Fatalf("expected Run() to succeed, got: %v", err)
		}

		trimmedOutput := strings.TrimSpace(output)
		trimmedExpect := strings.TrimSpace(string(dummyCertContent))
		if trimmedOutput != trimmedExpect {
			t.Errorf("expected output:\n%s\n\ngot:\n%s", trimmedExpect, trimmedOutput)
		}
	})

	t.Run("Fail when file is missing or invalid", func(t *testing.T) {
		cmd := &ReadCertCmd{
			Path: filepath.Join(tempDir, "missing.cert"),
		}

		_, err := captureStdout(func() error {
			return cmd.Run()
		})

		if err == nil {
			t.Fatal("expected error when reading a non-existent file, got nil")
		}
		expectedErrSubstr := "file does not contains valid certificate"
		if !strings.Contains(err.Error(), expectedErrSubstr) {
			t.Errorf("expected error to contain %q, got: %v", expectedErrSubstr, err)
		}
	})
}

func TestReadKeyCmd_Run(t *testing.T) {
	tempDir := t.TempDir()

	// Write an unencrypted dummy key
	unencryptedKeyPath := filepath.Join(tempDir, "unencrypted.key")
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	unencryptedContent := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	// Write an encrypted dummy key block (invalid PEM payload)
	encryptedKeyPath := filepath.Join(tempDir, "encrypted.key")
	encryptedContent := []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nENCRYPTED_MOCK_DATA\n-----END ENCRYPTED PRIVATE KEY-----\n")
	_ = os.WriteFile(encryptedKeyPath, encryptedContent, 0o600)

	// Write completely invalid (non-PEM) file
	corruptFilePath := filepath.Join(tempDir, "corrupt.key")
	_ = os.WriteFile(corruptFilePath, []byte("NOT_PEM_DATA_AT_ALL"), 0o600)

	t.Run("Successfully read unencrypted private key", func(t *testing.T) {
		cmd := &ReadKeyCmd{
			Path:    unencryptedKeyPath,
			Decrypt: false,
		}

		output, err := captureStdout(func() error {
			return cmd.Run()
		})

		if err != nil {
			t.Fatalf("expected Run() to succeed, got: %v", err)
		}

		trimmedOutput := strings.TrimSpace(output)
		trimmedExpect := strings.TrimSpace(string(unencryptedContent))
		if trimmedOutput != trimmedExpect {
			t.Errorf("expected output:\n%s\n\ngot:\n%s", trimmedExpect, trimmedOutput)
		}
	})

	t.Run("Fail when file is not a valid PEM block", func(t *testing.T) {
		cmd := &ReadKeyCmd{
			Path:    corruptFilePath,
			Decrypt: false,
		}

		_, err := captureStdout(func() error {
			return cmd.Run()
		})

		if err == nil {
			t.Fatal("expected error decoding non-PEM key, got nil")
		}
		expectedErrSubstr := "does not contains valid PEM encoded key"
		if !strings.Contains(err.Error(), expectedErrSubstr) {
			t.Errorf("expected error to contain %q, got: %v", expectedErrSubstr, err)
		}
	})

	t.Run("Attempt Decryption Fail (Master Key / Decrypt Routine dependency)", func(t *testing.T) {
		cmd := &ReadKeyCmd{
			Path:    encryptedKeyPath,
			Decrypt: true,
		}

		// Because decryption accesses your operating system's keyring directly via `utils.GetMasterKey()`,
		// this execution is expected to safely throw an OS-level file error or keyring missing error during a headless CI pipeline run.
		_, err := captureStdout(func() error {
			return cmd.Run()
		})

		if err == nil {
			t.Error("expected decryption run to fail under a mock keyless unit test environment, but completed without error")
		}
	})
}
