package utils

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestToNetIP_And_ToNetIPs(t *testing.T) {
	t.Run("ToNetIP Single Parse", func(t *testing.T) {
		tests := []struct {
			name      string
			input     string
			want      net.IP
			expectErr bool
		}{
			{"Valid IPv4", "192.168.1.1", net.ParseIP("192.168.1.1"), false},
			{"Valid IPv6", "2001:db8::1", net.ParseIP("2001:db8::1"), false},
			{"Invalid IP string", "999.999.999.999", nil, true},
			{"Empty string", "", nil, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := ToNetIP(tt.input)
				if (err != nil) != tt.expectErr {
					t.Fatalf("ToNetIP() error = %v, expectErr %v", err, tt.expectErr)
				}
				if !tt.expectErr && !got.Equal(tt.want) {
					t.Errorf("ToNetIP() = %v, want %v", got, tt.want)
				}
			})
		}
	})

	t.Run("ToNetIPs Batch Parse", func(t *testing.T) {
		input := []string{"192.168.1.1", "invalid-ip", "10.0.0.1"}
		want := []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")}
		got := ToNetIPs(input)

		if len(got) != len(want) {
			t.Fatalf("Expected slice length %d, got %d", len(want), len(got))
		}
		for i := range got {
			if !got[i].Equal(want[i]) {
				t.Errorf("At index %d: got %v, want %v", i, got[i], want[i])
			}
		}
	})
}

func TestToURL_And_ToURLs(t *testing.T) {
	t.Run("ToURL Single Parse", func(t *testing.T) {
		tests := []struct {
			name      string
			input     string
			expectErr bool
		}{
			{"Valid HTTP URL", "https://example.com", false},
			{"Valid relative URL", "/path/to/resource", false},
			{"Invalid control characters in URL", "http://\x7fexample.com", true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := ToURL(tt.input)
				if (err != nil) != tt.expectErr {
					t.Fatalf("ToURL() error = %v, expectErr %v", err, tt.expectErr)
				}
				if !tt.expectErr && got == nil {
					t.Error("ToURL() returned nil URL with no error")
				}
			})
		}
	})

	t.Run("ToURLs Batch Parse", func(t *testing.T) {
		input := []string{"https://example.com", "http://\x7fexample.com", "https://google.com"}
		got := ToURLs(input)

		if len(got) != 2 {
			t.Fatalf("Expected 2 valid URLs parsed, got %d", len(got))
		}
		if got[0].String() != "https://example.com" || got[1].String() != "https://google.com" {
			t.Errorf("URLs were parsed incorrectly: %v", got)
		}
	})
}

func TestToPem(t *testing.T) {
	inputBytes := []byte("secret-payload")
	blockType := "MY PRIVATE KEY"

	pemBytes := ToPem(inputBytes, blockType)
	if len(pemBytes) == 0 {
		t.Fatal("PEM bytes returned empty")
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("Failed to decode generated PEM block")
	}
	if block.Type != blockType {
		t.Errorf("Expected block type %q, got %q", blockType, block.Type)
	}
	if string(block.Bytes) != string(inputBytes) {
		t.Errorf("Expected decrypted payload %q, got %q", inputBytes, block.Bytes)
	}
}

func TestGetSerialNumber(t *testing.T) {
	s1, err := GetSerialNumber()
	if err != nil {
		t.Fatalf("Failed to generate first serial number: %v", err)
	}
	s2, err := GetSerialNumber()
	if err != nil {
		t.Fatalf("Failed to generate second serial number: %v", err)
	}

	if s1.Cmp(s2) == 0 {
		t.Error("Sequential serial numbers should be unique (collision occurred)")
	}
}

func TestJoinHomeDir(t *testing.T) {
	// Temporarily override the HOME/USERPROFILE env vars to point to a predictable location
	tempDir := t.TempDir()
	originalHome, ok := os.LookupEnv("HOME")
	originalUserProfile, okWin := os.LookupEnv("USERPROFILE")

	t.Setenv("HOME", tempDir)
	t.Setenv("USERPROFILE", tempDir)

	defer func() {
		if ok {
			_ = os.Setenv("HOME", originalHome)
		}
		if okWin {
			_ = os.Setenv("USERPROFILE", originalUserProfile)
		}
	}()

	tests := []struct {
		name     string
		filePath string
		want     string
	}{
		{"Path with home tilde", "~/certman/roots", filepath.Join(tempDir, "certman/roots")},
		{"Standard relative path", "certman/roots", "certman/roots"},
		{"Standard absolute path", "/var/lib/certman", "/var/lib/certman"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := JoinHomeDir(tt.filePath)
			if err != nil {
				t.Fatalf("JoinHomeDir() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("JoinHomeDir() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"Standard comma separated", "a,b,c", []string{"a", "b", "c"}},
		{"With extra spacing", "  apple,  banana , cherry ", []string{"apple", "banana", "cherry"}},
		{"Empty string input", "", nil},
		{"Spaces only", "   ", nil},
		{"Empty values in CSV", "a,,b", []string{"a", "b"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitCSV(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SplitCSV() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindDir(t *testing.T) {
	tempRootDir := t.TempDir()

	// Setup virtual folder tree
	targetDir := filepath.Join(tempRootDir, "sub1", "sub2", "target_folder")
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		t.Fatalf("Failed to create mock directory tree: %v", err)
	}

	tests := []struct {
		name      string
		rootDir   string
		target    string
		expectErr bool
	}{
		{"Target Directory exists", tempRootDir, "target_folder", false},
		{"Target Directory doesn't exist", tempRootDir, "non_existent", true},
		{"Walking an invalid path", filepath.Join(tempRootDir, "invalid"), "target_folder", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FindDir(tt.rootDir, tt.target)
			if (err != nil) != tt.expectErr {
				t.Fatalf("FindDir() error = %v, expectErr %v", err, tt.expectErr)
			}
			if !tt.expectErr && filepath.Base(got) != tt.target {
				t.Errorf("FindDir() returned incorrect path: %s", got)
			}
		})
	}
}

func TestToSnakeCase(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"Mixed Case and Spaces", "My CA Subject", "my_ca_subject"},
		{"Leading and trailing spacing", "  Common Name  ", "common_name"},
		{"Hyphens and underscores", "Root-CA_Certificate", "root_ca_certificate"},
		{"Multiple delimiters nested", "multiple---delimiters   here", "multiple_delimiters_here"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ToSnakeCase(tt.input)
			if got != tt.want {
				t.Errorf("ToSnakeCase() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetDeterministicPath(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	tests := []struct {
		name      string
		subjectCN string
		issuerCN  string
		isRootCA  bool
		want      string
	}{
		{
			name:      "Self-Signed Root CA",
			subjectCN: "My Root",
			issuerCN:  "My Root",
			isRootCA:  true,
			want:      filepath.Join(tempDir, "certman/certificates/roots/my_root"),
		},
		{
			name:      "Intermediate or Leaf Certificate",
			subjectCN: "My Leaf",
			issuerCN:  "My Root",
			isRootCA:  false,
			want:      filepath.Join(tempDir, "certman/certificates/issued_by/my_root/my_leaf"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetDeterministicPath(tt.subjectCN, tt.issuerCN, tt.isRootCA)
			if err != nil {
				t.Fatalf("GetDeterministicPath() error: %v", err)
			}
			if got != tt.want {
				t.Errorf("GetDeterministicPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseKeyUsages(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []x509.KeyUsage
	}{
		{
			name:  "Valid input strings with capitalization",
			input: []string{"digital-signature", " KEY-agreement ", "cert-sign"},
			want:  []x509.KeyUsage{x509.KeyUsageDigitalSignature, x509.KeyUsageKeyAgreement, x509.KeyUsageCertSign},
		},
		{
			name:  "Includes unrecognized inputs",
			input: []string{"digital-signature", "invalid-usage"},
			want:  []x509.KeyUsage{x509.KeyUsageDigitalSignature},
		},
		{
			name:  "Empty slices",
			input: []string{},
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseKeyUsages(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseKeyUsages() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseExtKeyUsages(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []x509.ExtKeyUsage
	}{
		{
			name:  "Valid Extended usages",
			input: []string{"server-auth", " client-auth", "code-signing"},
			want:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning},
		},
		{
			name:  "Contains junk metrics",
			input: []string{"ocsp-signing", "some-unsupported-thing"},
			want:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseExtKeyUsages(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseExtKeyUsages() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseTTLToHours(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      int
		expectErr bool
	}{
		{"Hours exact", "100h", 100, false},
		{"Days parsed to hours", "30d", 30 * 24, false},
		{"Years parsed to hours", "1y", 1 * 24 * 365, false},
		{"Incorrect units", "500m", 0, true},
		{"Missing units entirely", "1200", 0, true},
		{"Negative numbers", "-24h", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTTLToHours(tt.input)
			if (err != nil) != tt.expectErr {
				t.Fatalf("ParseTTLToHours() error = %v, expectErr %v", err, tt.expectErr)
			}
			if !tt.expectErr && got != tt.want {
				t.Errorf("ParseTTLToHours() = %d, want %d", got, tt.want)
			}
		})
	}
}
