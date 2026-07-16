package utils

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"reflect"
	"testing"
)

func TestGetKeyGenerators(t *testing.T) {
	t.Run("GetRSAKey", func(t *testing.T) {
		bits := 2048
		priv, pub, err := GetRSAKey(bits)
		if err != nil {
			t.Fatalf("GetRSAKey failed: %v", err)
		}
		if priv == nil || pub == nil {
			t.Fatal("Returned RSA keys should not be nil")
		}
		if priv.N.BitLen() < bits-1 || priv.N.BitLen() > bits+1 {
			t.Errorf("Expected RSA key size close to %d, got %d", bits, priv.N.BitLen())
		}
		if !priv.PublicKey.Equal(pub) {
			t.Error("Public key mismatch from generated RSA private key")
		}
	})

	t.Run("GetECDSAKey", func(t *testing.T) {
		curve := elliptic.P256()
		priv, pub, err := GetECDSAKey(curve)
		if err != nil {
			t.Fatalf("GetECDSAKey failed: %v", err)
		}
		if priv == nil || pub == nil {
			t.Fatal("Returned ECDSA keys should not be nil")
		}
		if priv.Curve != curve {
			t.Errorf("Expected curve %v, got %v", curve, priv.Curve)
		}
		if !priv.PublicKey.Equal(pub) {
			t.Error("Public key mismatch from generated ECDSA private key")
		}
	})

	t.Run("GetED25519Key", func(t *testing.T) {
		priv, pub, err := GetED25519Key()
		if err != nil {
			t.Fatalf("GetED25519Key failed: %v", err)
		}
		if len(priv) != ed25519.PrivateKeySize {
			t.Errorf("Expected private key length %d, got %d", ed25519.PrivateKeySize, len(priv))
		}
		if len(pub) != ed25519.PublicKeySize {
			t.Errorf("Expected public key length %d, got %d", ed25519.PublicKeySize, len(pub))
		}
		if !priv.Public().(ed25519.PublicKey).Equal(pub) {
			t.Error("Public key mismatch from generated Ed25519 private key")
		}
	})
}

func TestParseKey(t *testing.T) {
	// Generate real keys to serialize into various standard test vectors
	rsaKey, _ := rsa.GenerateKey(randReaderShim{}, 2048)
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), randReaderShim{})
	edKeyPub, edKeyPriv, _ := ed25519.GenerateKey(randReaderShim{})

	// Marshal Public Keys (All PKIX)
	rsaPubPKIX, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	ecdsaPubPKIX, _ := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	edPubPKIX, _ := x509.MarshalPKIXPublicKey(edKeyPub)

	// Marshal Private Keys (PKCS1, PKCS8, SEC1/EC)
	rsaPrivPKCS1 := x509.MarshalPKCS1PrivateKey(rsaKey)
	rsaPrivPKCS8, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	ecdsaPrivEC, _ := x509.MarshalECPrivateKey(ecdsaKey)
	ecdsaPrivPKCS8, _ := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	edPrivPKCS8, _ := x509.MarshalPKCS8PrivateKey(edKeyPriv)

	tests := []struct {
		name         string
		privBytes    []byte
		pubBytes     []byte
		wantPrivType reflect.Type
		wantPubType  reflect.Type
		expectErr    bool
	}{
		{
			name:         "RSA - PKCS1 Private & PKIX Public",
			privBytes:    rsaPrivPKCS1,
			pubBytes:     rsaPubPKIX,
			wantPrivType: reflect.TypeFor[*rsa.PrivateKey](),
			wantPubType:  reflect.TypeFor[*rsa.PublicKey](),
			expectErr:    false,
		},
		{
			name:         "RSA - PKCS8 Private & PKIX Public",
			privBytes:    rsaPrivPKCS8,
			pubBytes:     rsaPubPKIX,
			wantPrivType: reflect.TypeFor[*rsa.PrivateKey](),
			wantPubType:  reflect.TypeFor[*rsa.PublicKey](),
			expectErr:    false,
		},
		{
			name:         "ECDSA - SEC1 EC Private & PKIX Public",
			privBytes:    ecdsaPrivEC,
			pubBytes:     ecdsaPubPKIX,
			wantPrivType: reflect.TypeFor[*ecdsa.PrivateKey](),
			wantPubType:  reflect.TypeFor[*ecdsa.PublicKey](),
			expectErr:    false,
		},
		{
			name:         "ECDSA - PKCS8 Private & PKIX Public",
			privBytes:    ecdsaPrivPKCS8,
			pubBytes:     ecdsaPubPKIX,
			wantPrivType: reflect.TypeFor[*ecdsa.PrivateKey](),
			wantPubType:  reflect.TypeFor[*ecdsa.PublicKey](),
			expectErr:    false,
		},
		{
			name:         "Ed25519 - PKCS8 Private & PKIX Public",
			privBytes:    edPrivPKCS8,
			pubBytes:     edPubPKIX,
			wantPrivType: reflect.TypeFor[ed25519.PrivateKey](),
			wantPubType:  reflect.TypeFor[ed25519.PublicKey](),
			expectErr:    false,
		},
		{
			name:         "Invalid Public Key Standard (e.g. PKCS1 Public)",
			privBytes:    rsaPrivPKCS1,
			pubBytes:     x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey), // ParseKey expects PKIX
			wantPrivType: nil,
			wantPubType:  nil,
			expectErr:    true,
		},
		{
			name:         "Unrecognized Private Key Format",
			privBytes:    []byte("corrupt-private-key-bytes"),
			pubBytes:     rsaPubPKIX,
			wantPrivType: nil,
			wantPubType:  nil,
			expectErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPriv, gotPub, err := ParseKey(tt.privBytes, tt.pubBytes)
			if (err != nil) != tt.expectErr {
				t.Fatalf("ParseKey() error = %v, expectErr %v", err, tt.expectErr)
			}
			if tt.expectErr {
				return
			}

			if reflect.TypeOf(gotPriv) != tt.wantPrivType {
				t.Errorf("Private key type = %v, want %v", reflect.TypeOf(gotPriv), tt.wantPrivType)
			}
			if reflect.TypeOf(gotPub) != tt.wantPubType {
				t.Errorf("Public key type = %v, want %v", reflect.TypeOf(gotPub), tt.wantPubType)
			}
		})
	}
}

// randReaderShim helps satisfy crypto/rand reader without global state mutation
type randReaderShim struct{}

func (randReaderShim) Read(b []byte) (int, error) {
	return rand.Reader.Read(b)
}
