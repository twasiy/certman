// Copyright 2026 Tassok Imam Wasiy

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package utils

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func ToNetIP(addr string) (net.IP, error) {
	parsedIP := net.ParseIP(addr)
	if parsedIP == nil {
		return nil, errors.New("unknown or invalid ip address")
	}

	return parsedIP, nil
}

func ToNetIPs(addrs []string) []net.IP {
	var netIPs []net.IP

	for _, ip := range addrs {
		netIP, err := ToNetIP(ip)
		if err != nil {
			log.Printf("skipping invalid IP string: %s\n", ip)
			continue
		}
		netIPs = append(netIPs, netIP)
	}
	return netIPs
}

func ToURL(s string) (*url.URL, error) {
	parsedUrl, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("unknown or invalid url")
	}

	return parsedUrl, nil
}

func ToURLs(urls []string) []*url.URL {
	var urlURLs []*url.URL

	for _, urlStr := range urls {
		u, err := ToURL(urlStr)
		if err != nil {
			log.Printf("skipping invalid URL string: %s\n", urlStr)
			continue
		}
		urlURLs = append(urlURLs, u)
	}
	return urlURLs
}

func GetSerialNumber() (*big.Int, error) {
	sNumLim := new(big.Int).Lsh(big.NewInt(1), 128)
	sNum, err := rand.Int(rand.Reader, sNumLim)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	return sNum, nil
}

func JoinHomeDir(filePath string) (string, error) {
	if strings.HasPrefix(filePath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get home directory: %w", err)
		}
		resolvedPath := filepath.Join(home, filePath[2:])
		return resolvedPath, nil
	}
	return filePath, nil
}

func SplitCSV(in string) []string {
	if strings.TrimSpace(in) == "" {
		return nil
	}
	var out []string
	for segment := range strings.SplitSeq(in, ",") {
		if trimmed := strings.TrimSpace(segment); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// ToSnakeCase converts a string to lowercase and replaces spaces/special characters with underscores.
func ToSnakeCase(str string) string {
	lower := strings.ToLower(strings.TrimSpace(str))

	// 2. Replace one or more consecutive spaces, hyphens, or special chars with a single underscore
	reg := regexp.MustCompile(`[\s\-_]+`)
	snake := reg.ReplaceAllString(lower, "_")

	return snake
}

func ParseKeyUsages(usages []string) []x509.KeyUsage {
	var out []x509.KeyUsage
	m := map[string]x509.KeyUsage{
		"digital-signature":  x509.KeyUsageDigitalSignature,
		"content-commitment": x509.KeyUsageContentCommitment,
		"key-encipherment":   x509.KeyUsageKeyEncipherment,
		"data-encipherment":  x509.KeyUsageDataEncipherment,
		"key-agreement":      x509.KeyUsageKeyAgreement,
		"cert-sign":          x509.KeyUsageCertSign,
		"crl-sign":           x509.KeyUsageCRLSign,
		"encipher-only":      x509.KeyUsageEncipherOnly,
		"decipher-only":      x509.KeyUsageDecipherOnly,
	}
	for _, u := range usages {
		if ku, exists := m[strings.ToLower(strings.TrimSpace(u))]; exists {
			out = append(out, ku)
		}
	}
	return out
}

func ParseExtKeyUsages(usages []string) []x509.ExtKeyUsage {
	var out []x509.ExtKeyUsage
	m := map[string]x509.ExtKeyUsage{
		"any":              x509.ExtKeyUsageAny,
		"server-auth":      x509.ExtKeyUsageServerAuth,
		"client-auth":      x509.ExtKeyUsageClientAuth,
		"code-signing":     x509.ExtKeyUsageCodeSigning,
		"email-protection": x509.ExtKeyUsageEmailProtection,
		"time-stamping":    x509.ExtKeyUsageTimeStamping,
		"ocsp-signing":     x509.ExtKeyUsageOCSPSigning,
	}
	for _, u := range usages {
		if eku, exists := m[strings.ToLower(strings.TrimSpace(u))]; exists {
			out = append(out, eku)
		}
	}
	return out
}

func MarshalKeyUsage(usage x509.KeyUsage) []string {
	var out []string
	m := map[x509.KeyUsage]string{
		x509.KeyUsageDigitalSignature:  "digital-signature",
		x509.KeyUsageContentCommitment: "content-commitment",
		x509.KeyUsageKeyEncipherment:   "key-encipherment",
		x509.KeyUsageDataEncipherment:  "data-encipherment",
		x509.KeyUsageKeyAgreement:      "key-agreement",
		x509.KeyUsageCertSign:          "cert-sign",
		x509.KeyUsageCRLSign:           "crl-sign",
		x509.KeyUsageEncipherOnly:      "encipher-only",
		x509.KeyUsageDecipherOnly:      "decipher-only",
	}

	for ku, name := range m {
		if usage&ku > 0 {
			out = append(out, name)
		}
	}
	return out
}

func MarshalExtKeyUsages(extUsages []x509.ExtKeyUsage) []string {
	var out []string
	m := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:             "any",
		x509.ExtKeyUsageServerAuth:      "server-auth",
		x509.ExtKeyUsageClientAuth:      "client-auth",
		x509.ExtKeyUsageCodeSigning:     "code-signing",
		x509.ExtKeyUsageEmailProtection: "email-protection",
		x509.ExtKeyUsageTimeStamping:    "time-stamping",
		x509.ExtKeyUsageOCSPSigning:     "ocsp-signing",
	}

	for _, eku := range extUsages {
		if name, exists := m[eku]; exists {
			out = append(out, name)
		}
	}
	return out
}

// ParseRevocationReason maps a single string input to an RFC 5280 integer code.
func ParseRevocationReason(reason string) (int, error) {
	m := map[string]int{
		"unspecified":            0,
		"key-compromise":         1,
		"ca-compromise":          2,
		"affiliation-changed":    3,
		"superseded":             4,
		"cessation-of-operation": 5,
		"certificate-hold":       6,
		"remove-from-crl":        8,
		"privilege-withdrawn":    9,
		"a-a-compromise":         10,
	}

	cleaned := strings.ToLower(strings.TrimSpace(reason))
	if code, exists := m[cleaned]; exists {
		return code, nil
	}

	return 0, errors.New("invalid revocation reason: " + reason)
}

// MarshalRevocationReason converts a single integer code back to its string representation.
func MarshalRevocationReason(code int) (string, error) {
	m := map[int]string{
		0:  "unspecified",
		1:  "key-compromise",
		2:  "ca-compromise",
		3:  "affiliation-changed",
		4:  "superseded",
		5:  "cessation-of-operation",
		6:  "certificate-hold",
		8:  "remove-from-crl",
		9:  "privilege-withdrawn",
		10: "a-a-compromise",
	}

	if name, exists := m[code]; exists {
		return name, nil
	}

	return "", errors.New("unknown revocation code")
}

var durationRegex = regexp.MustCompile(`^(\d+)([hdy])$`)

// ParseTTLToHours parses duration strings like "1000h", "30d", "10y" into total hours.
func ParseTTLToHours(ttlStr string) (int, error) {
	matches := durationRegex.FindStringSubmatch(ttlStr)
	if len(matches) != 3 {
		return 0, fmt.Errorf("invalid duration format %q: must be a number followed by 'h', 'd', or 'y' (e.g., 1000h, 30d, 10y)", ttlStr)
	}

	value, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, fmt.Errorf("invalid number in duration: %v", err)
	}

	unit := matches[2]
	switch unit {
	case "h":
		return value, nil
	case "d":
		return value * 24, nil
	case "y":
		// Approximating a year as 365 days (8760 hours)
		return value * 24 * 365, nil
	default:
		return 0, fmt.Errorf("unsupported time unit: %s", unit)
	}
}

// GenerateKeyName appends a Unix timestamp to the common name
func GenerateKeyName(commonName string) string {
	return fmt.Sprintf("%s-%d", commonName, time.Now().Unix())
}

func EncodeToPem(bytes []byte, blockType string) (string, error) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: bytes,
	})

	if pemBytes == nil {
		return "", errors.New("failed to encode to pem")
	}

	return string(pemBytes), nil
}

func DecodeToPem(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM bytes")
	}
	return block.Bytes, nil
}

func ReturnPrivPubPem(privateKey any, publicKey any) (string, string, error) {
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	masterKey, err := GetMasterKey()
	if err != nil {
		return "", "", fmt.Errorf("failed to get master key from os keyring: %w", err)
	}
	privBytesBlob, err := Encrypt(privBytes, masterKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt private key: %w", err)
	}
	privBlobPem, err := EncodeToPem(privBytesBlob, "ENCRYPTED PRIVATE KEY")
	if err != nil {
		return "", "", err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubPem, err := EncodeToPem(pubBytes, "PUBLIC KEY")
	if err != nil {
		return "", "", err
	}

	return privBlobPem, pubPem, nil
}

func ParseCertificate(pemBytes []byte) (*x509.Certificate, error) {
	certBytes, err := DecodeToPem(pemBytes)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Certificate: %w", err)
	}
	return cert, nil
}

func DecryptPrivKey(privPem []byte) ([]byte, error) {
	privKey, err := DecodeToPem(privPem)
	if err != nil {
		return nil, err
	}

	masterKey, err := GetMasterKey()
	if err != nil {
		return nil, err
	}

	decryptedPrivKey, err := Decrypt(privKey, masterKey)
	if err != nil {
		return nil, err
	}

	return decryptedPrivKey, nil
}

func ParseKeys(privPem []byte, pubPem []byte) (any, any, error) {
	decryptedPrivKey, err := DecryptPrivKey(privPem)
	if err != nil {
		return nil, nil, err
	}
	pubKey, err := DecodeToPem(pubPem)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(decryptedPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	publicKey, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return privateKey, publicKey, nil
}

func GetKeyDetails(key any) (algoType string, sizeInfo string) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		algoType = "RSA Private Key"
		sizeInfo = fmt.Sprintf("%d-bit", k.Size()*8)
	case *ecdsa.PrivateKey:
		algoType = "ECDSA Private Key"
		sizeInfo = fmt.Sprintf("Curve: %s", k.Params().Name)
	case ed25519.PrivateKey:
		algoType = "Ed25519 Private Key"
		sizeInfo = "256-bit seed"
	case *rsa.PublicKey:
		algoType = "RSA Public Key"
		sizeInfo = fmt.Sprintf("%d-bit", k.Size()*8)
	case *ecdsa.PublicKey:
		algoType = "ECDSA Public Key"
		sizeInfo = fmt.Sprintf("Curve: %s", k.Params().Name)
	case ed25519.PublicKey:
		algoType = "Ed25519 Public Key"
		sizeInfo = "256-bit"
	default:
		algoType = fmt.Sprintf("Unknown (%T)", key)
		sizeInfo = "N/A"
	}
	return algoType, sizeInfo
}

func TruncateHex(b []byte) string {
	if len(b) == 0 {
		return "empty"
	}
	fullHex := hex.EncodeToString(b)
	if len(fullHex) > 32 {
		return fullHex[:32]
	}
	return fullHex
}

// Formats a byte slice fingerprint into standard double-spaced format (e.g., "AA:BB:CC:...")
func FormatFingerprint(b []byte) string {
	var parts []string
	for _, val := range b {
		parts = append(parts, fmt.Sprintf("%02X", val))
	}
	return strings.Join(parts, ":")
}

func ParseCRL(pemBytes []byte) (*x509.RevocationList, error) {
	crlBytes, err := DecodeToPem(pemBytes)
	if err != nil {
		return nil, err
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Revocation List: %w", err)
	}
	return crl, nil
}

// Structural definition for parsing RFC 5280 Authority Key Identifier
type authKeyIdentifier struct {
	KeyIdentifier []byte `asn1:"optional,tag:0"`
}

// ExtractAuthorityKeyID extracts the raw AKID bytes from a certificate extensions block
func ExtractAuthorityKeyID(cert *x509.Certificate) ([]byte, error) {
	// OID 2.5.29.35 represents Authority Key Identifier
	for _, ext := range cert.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 35}) {
			var akid authKeyIdentifier
			_, err := asn1.Unmarshal(ext.Value, &akid)
			if err != nil {
				return nil, err
			}
			return akid.KeyIdentifier, nil
		}
	}
	return nil, fmt.Errorf("authority key identifier extension not found")
}

// IsSelfSigned checks if a certificate's subject matches its issuer (Self-signed Root CA check)
func IsSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

// SanitizeFilename safely truncates path operators and filters malicious special characters
func SanitizeFilename(input string, fallback string) string {
	cleaned := strings.ReplaceAll(input, "..", "")
	cleaned = strings.ReplaceAll(cleaned, "/", "")
	cleaned = strings.ReplaceAll(cleaned, "\\", "")

	reg := regexp.MustCompile(`[^a-zA-Z0-9_\-\. ]+`)
	cleaned = reg.ReplaceAllString(cleaned, "")

	cleaned = strings.TrimSpace(cleaned)

	if cleaned == "" || cleaned == "." || cleaned == ".." {
		return fallback
	}

	if len(cleaned) > 200 {
		cleaned = cleaned[:200]
	}

	return cleaned
}

// GetSignatureAlgorithm maps a CLI string input to the correct x509 SignatureAlgorithm
func GetSignatureAlgorithm(keyType string) (x509.SignatureAlgorithm, error) {
	switch keyType {
	case "rsa-2048", "rsa-4096":
		return x509.SHA256WithRSA, nil
	case "ecdsa-224":
		return x509.ECDSAWithSHA1, nil // SHA1 is standard for P-224, but consider upgrading keyType if security allows
	case "ecdsa-256":
		return x509.ECDSAWithSHA256, nil
	case "ecdsa-384":
		return x509.ECDSAWithSHA384, nil
	case "ecdsa-521":
		return x509.ECDSAWithSHA512, nil
	case "ed25519":
		return x509.PureEd25519, nil
	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported or invalid key type: %s", keyType)
	}
}

func ResolveDestinationPath(inputPath, defaultName, defaultExt string) (string, error) {
	defaultFilename := SanitizeFilename(defaultName, "exported_item") + defaultExt
	if inputPath == "" {
		return defaultFilename, nil
	}

	resolvedPath, err := JoinHomeDir(inputPath)
	if err != nil {
		return "", err
	}

	if fi, err := os.Stat(resolvedPath); err == nil {
		if fi.IsDir() {
			return filepath.Join(resolvedPath, defaultFilename), nil
		}
		return resolvedPath, nil
	}

	if strings.HasSuffix(inputPath, "/") || strings.HasSuffix(inputPath, "\\") || filepath.Ext(resolvedPath) == "" {
		return filepath.Join(resolvedPath, defaultFilename), nil
	}

	return resolvedPath, nil
}

func ReadFile(path string) ([]byte, error) {
	fullPath, err := JoinHomeDir(path)
	if err != nil {
		return nil, err
	}

	bytes, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return bytes, nil
}

func IpSlicesEqual(ips1, ips2 []net.IP) bool {
	if len(ips1) != len(ips2) {
		return false
	}
	for i := range ips1 {
		if !ips1[i].Equal(ips2[i]) {
			return false
		}
	}
	return true
}

func FormatIPs(ips []net.IP) string {
	var strIPs []string
	for _, ip := range ips {
		strIPs = append(strIPs, ip.String())
	}
	return strings.Join(strIPs, ", ")
}

func UriSlicesEqual(u1, u2 []*url.URL) bool {
	if len(u1) != len(u2) {
		return false
	}
	for i := range u1 {
		if u1[i].String() != u2[i].String() {
			return false
		}
	}
	return true
}

func FormatURIs(uris []*url.URL) string {
	var strURIs []string
	for _, u := range uris {
		strURIs = append(strURIs, u.String())
	}
	return strings.Join(strURIs, ", ")
}

func ParseCSR(pemStr string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid CSR PEM format")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}
