package utils

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEncryptAndDecrypt_Success(t *testing.T) {
	// Generate valid test keys of different AES sizes
	key128 := make([]byte, 16) // AES-128
	key192 := make([]byte, 24) // AES-192
	key256 := make([]byte, 32) // AES-256

	for _, k := range [][]byte{key128, key192, key256} {
		if _, err := rand.Read(k); err != nil {
			t.Fatalf("Failed to generate random key: %v", err)
		}
	}

	tests := []struct {
		name      string
		masterKey []byte
		plaintext []byte
	}{
		{
			name:      "AES-128 Standard Plaintext",
			masterKey: key128,
			plaintext: []byte("Hello, secure world!"),
		},
		{
			name:      "AES-192 Empty Plaintext",
			masterKey: key192,
			plaintext: []byte(""),
		},
		{
			name:      "AES-256 Large Plaintext",
			masterKey: key256,
			plaintext: bytes.Repeat([]byte("A"), 4096),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := Encrypt(tt.plaintext, tt.masterKey)
			if err != nil {
				t.Fatalf("Encrypt() unexpected error: %v", err)
			}

			if len(ciphertext) == 0 && len(tt.plaintext) > 0 {
				t.Error("Encrypt() returned empty ciphertext for non-empty plaintext")
			}

			// Decrypt
			decrypted, err := Decrypt(ciphertext, tt.masterKey)
			if err != nil {
				t.Fatalf("Decrypt() unexpected error: %v", err)
			}

			// Compare results
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("Decrypt() got = %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEncryptAndDecrypt_Errors(t *testing.T) {
	validKey := make([]byte, 32)
	rand.Read(validKey)

	t.Run("Invalid Key Sizes", func(t *testing.T) {
		invalidKeys := []struct {
			name string
			key  []byte
		}{
			{"Too short key", []byte("short-key")},
			{"Incorrect mid-size key", make([]byte, 31)},
			{"Empty key", []byte{}},
		}

		for _, tt := range invalidKeys {
			t.Run(tt.name, func(t *testing.T) {
				_, err := Encrypt([]byte("data"), tt.key)
				if err == nil {
					t.Error("Expected Encrypt to fail with invalid key size, but got nil error")
				}

				_, err = Decrypt([]byte("data"), tt.key)
				if err == nil {
					t.Error("Expected Decrypt to fail with invalid key size, but got nil error")
				}
			})
		}
	})

	t.Run("Decryption Failure Cases", func(t *testing.T) {
		plaintext := []byte("highly-sensitive-payload")
		ciphertext, err := Encrypt(plaintext, validKey)
		if err != nil {
			t.Fatalf("Setup encryption failed: %v", err)
		}

		// Create a separate wrong key
		wrongKey := make([]byte, 32)
		rand.Read(wrongKey)

		tests := []struct {
			name       string
			key        []byte
			ciphertext []byte
		}{
			{
				name:       "Decrypt with wrong key",
				key:        wrongKey,
				ciphertext: ciphertext,
			},
			{
				name:       "Ciphertext too short (under nonce size)",
				key:        validKey,
				ciphertext: []byte("too-short"),
			},
			{
				name:       "Tampered Ciphertext payload",
				key:        validKey,
				ciphertext: append(ciphertext[:len(ciphertext)-1], ciphertext[len(ciphertext)-1]^0xFF), // Flip last bit
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := Decrypt(tt.ciphertext, tt.key)
				if err == nil {
					t.Error("Expected decryption to fail, but got nil error")
				}
			})
		}
	})
}
