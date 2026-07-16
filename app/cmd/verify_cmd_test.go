package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

// Helper structures to keep track of generated assets on disk
type testCertAsset struct {
	CertPath string
	KeyPath  string
	Cert     *x509.Certificate
	PrivKey  any
}

// Generates a mock x509 cert chain on disk (Root -> Intermediate -> Leaf) using ECDSA
func generateMockECDSAChain(t *testing.T, tempDir string) (root, inter, leaf testCertAsset) {
	t.Helper()

	// Root Keys & Cert
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Mock Test Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDer, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create root cert: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDer)

	// Intermediate Keys & Cert (signed by Root)
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate intermediate key: %v", err)
	}
	interTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(101),
		Subject:               pkix.Name{CommonName: "Mock Test Intermediate CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(5 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	interDer, err := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create intermediate cert: %v", err)
	}
	interCert, _ := x509.ParseCertificate(interDer)

	// Leaf Keys & Cert (signed by Intermediate)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(102),
		Subject:      pkix.Name{CommonName: "api.mock.test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(2 * time.Hour),
		DNSNames:     []string{"api.mock.test"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDer, err := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("failed to create leaf cert: %v", err)
	}
	leafCert, _ := x509.ParseCertificate(leafDer)

	// Write PEM files helper
	writePEM := func(name string, certBytes []byte, keyAny any) (string, string) {
		cP := filepath.Join(tempDir, name+".crt")
		kP := filepath.Join(tempDir, name+".key")

		cFile, _ := os.Create(cP)
		_ = pem.Encode(cFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
		cFile.Close()

		kFile, _ := os.Create(kP)
		var blockType string
		var keyBytes []byte
		switch k := keyAny.(type) {
		case *ecdsa.PrivateKey:
			blockType = "EC PRIVATE KEY"
			keyBytes, _ = x509.MarshalECPrivateKey(k)
		case *rsa.PrivateKey:
			blockType = "RSA PRIVATE KEY"
			keyBytes = x509.MarshalPKCS1PrivateKey(k)
		case ed25519.PrivateKey:
			blockType = "PRIVATE KEY"
			keyBytes, _ = x509.MarshalPKCS8PrivateKey(k)
		}
		_ = pem.Encode(kFile, &pem.Block{Type: blockType, Bytes: keyBytes})
		kFile.Close()

		return cP, kP
	}

	rC, rK := writePEM("root", rootDer, rootKey)
	iC, iK := writePEM("intermediate", interDer, interKey)
	lC, lK := writePEM("leaf", leafDer, leafKey)

	return testCertAsset{CertPath: rC, KeyPath: rK, Cert: rootCert, PrivKey: rootKey},
		testCertAsset{CertPath: iC, KeyPath: iK, Cert: interCert, PrivKey: interKey},
		testCertAsset{CertPath: lC, KeyPath: lK, Cert: leafCert, PrivKey: leafKey}
}

// Helper to write keys of other algorithms (RSA & Ed25519) to verify cross-algorithm key checking
func writeSpecificKeyPair(t *testing.T, tempDir, prefix, algo string) (string, string) {
	t.Helper()
	var priv crypto.PrivateKey
	var pub crypto.PublicKey
	var err error

	switch algo {
	case "rsa":
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		priv = k
		pub = &k.PublicKey
	case "ed25519":
		pubEd, privEd, _ := ed25519.GenerateKey(rand.Reader)
		priv = privEd
		pub = pubEd
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(500),
		Subject:      pkix.Name{CommonName: "CrossAlgoCheck"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("failed to construct self-signed %s: %v", algo, err)
	}

	cP := filepath.Join(tempDir, prefix+".crt")
	kP := filepath.Join(tempDir, prefix+".key")

	cFile, _ := os.Create(cP)
	_ = pem.Encode(cFile, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cFile.Close()

	kFile, _ := os.Create(kP)
	var bType string
	var bBytes []byte
	if algo == "rsa" {
		bType = "RSA PRIVATE KEY"
		bBytes = x509.MarshalPKCS1PrivateKey(priv.(*rsa.PrivateKey))
	} else {
		bType = "PRIVATE KEY"
		bBytes, _ = x509.MarshalPKCS8PrivateKey(priv)
	}
	_ = pem.Encode(kFile, &pem.Block{Type: bType, Bytes: bBytes})
	kFile.Close()

	return cP, kP
}

func TestVerifyCertCmd_Run(t *testing.T) {
	tempDir := t.TempDir()
	root, inter, leaf := generateMockECDSAChain(t, tempDir)

	t.Run("Valid Self-Signed Root Chain Verification", func(t *testing.T) {
		vc := &VerifyCertCmd{
			Path:   root.CertPath,
			Issuer: root.CertPath, // Root issuer points to itself
		}
		err := vc.Run()
		if err != nil {
			t.Fatalf("Self-signed root CA verification should succeed, got: %v", err)
		}
	})

	t.Run("Valid Intermediate Verification (Requires Root Path)", func(t *testing.T) {
		vc := &VerifyCertCmd{
			Path:    leaf.CertPath,
			Issuer:  inter.CertPath,
			Root:    root.CertPath,
			DNSName: "api.mock.test",
		}
		err := vc.Run()
		if err != nil {
			t.Fatalf("Full trust chain validation failed: %v", err)
		}
	})

	t.Run("Fails with Intermediate Issuer but Missing Root Path", func(t *testing.T) {
		vc := &VerifyCertCmd{
			Path:   leaf.CertPath,
			Issuer: inter.CertPath, // Intermediate issuer
			Root:   "",             // Missing Root reference
		}
		err := vc.Run()
		if err == nil {
			t.Fatal("Expected run to fail due to missing root path on an intermediate chain, got nil")
		}
		expectedErrSubstr := "must provide the --root path"
		if !strings.Contains(err.Error(), expectedErrSubstr) {
			t.Errorf("Expected error containing %q, got: %v", expectedErrSubstr, err)
		}
	})

	t.Run("Fails validation for DNSName mismatch", func(t *testing.T) {
		vc := &VerifyCertCmd{
			Path:    leaf.CertPath,
			Issuer:  inter.CertPath,
			Root:    root.CertPath,
			DNSName: "malicious-site.com", // Incorrect Subject Alternative Name (SAN)
		}
		err := vc.Run()
		if err == nil {
			t.Fatal("Expected error due to non-matching DNSName verification constraint, got nil")
		}
	})
}

func TestVerifyKeyCmd_Run(t *testing.T) {
	tempDir := t.TempDir()
	_, _, leaf := generateMockECDSAChain(t, tempDir)
	rsaCert, rsaKey := writeSpecificKeyPair(t, tempDir, "rsa_check", "rsa")
	ed25519Cert, ed25519Key := writeSpecificKeyPair(t, tempDir, "ed_check", "ed25519")
	_, rsaKey2 := writeSpecificKeyPair(t, tempDir, "rsa_check", "rsa")

	tests := []struct {
		name      string
		certPath  string
		keyPath   string
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "ECDSA - Perfect Cryptographic Match",
			certPath: leaf.CertPath,
			keyPath:  leaf.KeyPath,
			wantErr:  false,
		},
		{
			name:     "RSA - Perfect Cryptographic Match",
			certPath: rsaCert,
			keyPath:  rsaKey,
			wantErr:  false,
		},
		{
			name:     "Ed25519 - Perfect Cryptographic Match",
			certPath: ed25519Cert,
			keyPath:  ed25519Key,
			wantErr:  false,
		},
		{
			name:      "Type Mismatch - ECDSA Cert with RSA Key",
			certPath:  leaf.CertPath,
			keyPath:   rsaKey,
			wantErr:   true,
			errSubstr: "key mismatch: certificate holds an ECDSA public key, but the private key is not ECDSA",
		},
		{
			name:      "Type Mismatch - RSA Cert with Ed25519 Key",
			certPath:  rsaCert,
			keyPath:   ed25519Key,
			wantErr:   true,
			errSubstr: "key mismatch: certificate holds an RSA public key, but the private key is not RSA",
		},
		{
			name:      "Cryptographic Mismatch - Correct Key Type But Non-Matching Key Pair",
			certPath:  leaf.CertPath,
			keyPath:   rsaKey2,
			wantErr:   true,
			errSubstr: "key mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vk := &VerifyKeyCmd{
				Cert:    tt.certPath,
				Key:     tt.keyPath,
				Decrypt: false,
			}
			err := vk.Run()
			if (err != nil) != tt.wantErr {
				t.Fatalf("VerifyKeyCmd.Run() mismatch. Expected error: %v, got: %v", tt.wantErr, err)
			}
			if tt.wantErr && err != nil {
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("Expected error containing %q, got: %v", tt.errSubstr, err)
				}
			}
		})
	}

	t.Run("Cryptographic Mismatch - Matching ECDSA Key types with disparate private keys", func(t *testing.T) {
		// Generate an isolated second ECDSA key pair
		otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		otherKeyBytes, _ := x509.MarshalECPrivateKey(otherKey)
		otherKeyPath := filepath.Join(tempDir, "isolated_mismatch.key")

		f, _ := os.Create(otherKeyPath)
		_ = pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: otherKeyBytes})
		f.Close()

		vk := &VerifyKeyCmd{
			Cert: leaf.CertPath, // Valid ecdsa cert
			Key:  otherKeyPath,  // Valid but mismatching ecdsa key
		}

		err := vk.Run()
		if err == nil {
			t.Fatal("Expected verification error for non-matching ECDSA keys, got nil")
		}
		if !strings.Contains(err.Error(), "cryptographic mismatch") {
			t.Errorf("Expected signature mismatch warning, got: %v", err)
		}
	})
}
