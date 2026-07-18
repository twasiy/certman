package utils

import (
	"crypto/rand"
	"crypto/x509"
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

func ToPem(bytes []byte, blockType string) []byte {
	block := pem.Block{
		Bytes: bytes,
		Type:  blockType,
	}
	pemBytes := pem.EncodeToMemory(&block)

	return pemBytes
}

func GetSerialNumber() (*big.Int, error) {
	sNumLim := new(big.Int).Lsh(big.NewInt(1), 128)
	sNum, err := rand.Int(rand.Reader, sNumLim)
	if err != nil {
		return nil, fmt.Errorf("cannot generate serial number: %w", err)
	}
	return sNum, nil
}

func JoinHomeDir(filePath string) (string, error) {
	if strings.HasPrefix(filePath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot get home directory: %w", err)
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
