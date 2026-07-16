package domain

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"reflect"
	"testing"
)

func TestGetKey(t *testing.T) {
	tests := []struct {
		name         string
		keyType      KeyType
		wantPrivType reflect.Type
		wantPubType  reflect.Type
		expectErr    bool
	}{
		{
			name:         "Generate RSA 2048 KeyPair",
			keyType:      RSA_2048,
			wantPrivType: reflect.TypeFor[*rsa.PrivateKey](),
			wantPubType:  reflect.TypeFor[*rsa.PublicKey](),
			expectErr:    false,
		},
		{
			name:         "Generate RSA 4096 KeyPair",
			keyType:      RSA_4096,
			wantPrivType: reflect.TypeFor[*rsa.PrivateKey](),
			wantPubType:  reflect.TypeFor[*rsa.PublicKey](),
			expectErr:    false,
		},
		{
			name:         "Generate ECDSA P-224 KeyPair",
			keyType:      ECDSA_P224,
			wantPrivType: reflect.TypeFor[*ecdsa.PrivateKey](),
			wantPubType:  reflect.TypeFor[*ecdsa.PublicKey](),
			expectErr:    false,
		},
		{
			name:         "Generate ECDSA P-256 KeyPair",
			keyType:      ECDSA_P256,
			wantPrivType: reflect.TypeFor[*ecdsa.PrivateKey](),
			wantPubType:  reflect.TypeFor[*ecdsa.PublicKey](),
			expectErr:    false,
		},
		{
			name:         "Generate ECDSA P-384 KeyPair",
			keyType:      ECDSA_P384,
			wantPrivType: reflect.TypeFor[*ecdsa.PrivateKey](),
			wantPubType:  reflect.TypeFor[*ecdsa.PublicKey](),
			expectErr:    false,
		},
		{
			name:         "Generate ECDSA P-521 KeyPair",
			keyType:      ECDSA_P521,
			wantPrivType: reflect.TypeFor[*ecdsa.PrivateKey](),
			wantPubType:  reflect.TypeFor[*ecdsa.PublicKey](),
			expectErr:    false,
		},
		{
			name:         "Generate ED25519 KeyPair",
			keyType:      ED25519,
			wantPrivType: reflect.TypeFor[ed25519.PrivateKey](),
			wantPubType:  reflect.TypeFor[ed25519.PublicKey](),
			expectErr:    false,
		},
		{
			name:         "Unsupported Key Type",
			keyType:      UNKNOWN,
			wantPrivType: nil,
			wantPubType:  nil,
			expectErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := GetKey(tt.keyType)
			if (err != nil) != tt.expectErr {
				t.Fatalf("GetKey() error = %v, expectErr %v", err, tt.expectErr)
			}
			if tt.expectErr {
				if keyPair != nil {
					t.Error("Expected nil KeyPair on error, but got a non-nil object")
				}
				return
			}

			if keyPair == nil {
				t.Fatal("Returned KeyPair is nil")
			}

			// Validate concrete private and public key type structures
			if reflect.TypeOf(keyPair.PrivateKey) != tt.wantPrivType {
				t.Errorf("PrivateKey type = %v, want %v", reflect.TypeOf(keyPair.PrivateKey), tt.wantPrivType)
			}
			if reflect.TypeOf(keyPair.PublicKey) != tt.wantPubType {
				t.Errorf("PublicKey type = %v, want %v", reflect.TypeOf(keyPair.PublicKey), tt.wantPubType)
			}

			// Perform sanity check depending on the generated structures
			switch k := keyPair.PrivateKey.(type) {
			case *rsa.PrivateKey:
				if err := k.Validate(); err != nil {
					t.Errorf("Generated RSA key is invalid: %v", err)
				}
			case *ecdsa.PrivateKey:
				var expectedCurve elliptic.Curve
				switch tt.keyType {
				case ECDSA_P224:
					expectedCurve = elliptic.P224()
				case ECDSA_P256:
					expectedCurve = elliptic.P256()
				case ECDSA_P384:
					expectedCurve = elliptic.P384()
				case ECDSA_P521:
					expectedCurve = elliptic.P521()
				}
				if k.Curve != expectedCurve {
					t.Errorf("Expected ECDSA Curve %v, got %v", expectedCurve, k.Curve)
				}
			}
		})
	}
}

func TestGenerateSKID(t *testing.T) {
	// Generate valid RSA keys to extract public key
	rsaKeyPair, err := GetKey(RSA_2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA KeyPair for SKID test: %v", err)
	}

	ecdsaKeyPair, err := GetKey(ECDSA_P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA KeyPair for SKID test: %v", err)
	}

	tests := []struct {
		name      string
		pubKey    any
		expectErr bool
	}{
		{
			name:      "Valid RSA Public Key SKID Generation",
			pubKey:    rsaKeyPair.PublicKey,
			expectErr: false,
		},
		{
			name:      "Valid ECDSA Public Key SKID Generation",
			pubKey:    ecdsaKeyPair.PublicKey,
			expectErr: false,
		},
		{
			name:      "Invalid Public Key (Wrong Type / Nil)",
			pubKey:    nil,
			expectErr: true,
		},
		{
			name:      "Invalid Public Key structure (Unsupported value type)",
			pubKey:    "not-a-public-key",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skid, err := generateSKID(tt.pubKey)
			if (err != nil) != tt.expectErr {
				t.Fatalf("generateSKID() error = %v, expectErr %v", err, tt.expectErr)
			}
			if !tt.expectErr {
				// RFC 5280 method 1 produces a 160-bit (20-byte) SHA-1 hash
				if len(skid) != 20 {
					t.Errorf("Expected 20-byte SKID (SHA-1), got %d bytes", len(skid))
				}
			}
		})
	}
}
