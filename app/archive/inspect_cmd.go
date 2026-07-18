package archive

import (
	"certman/app/utils"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type InspectCmd struct {
	Cert InspectCertCmd `cmd:"" help:"Prints raw Certificate in stdout."`
	Key  InspectKeyCmd  `cmd:"" help:"Prints raw Key in stdout."`
}

type InspectCertCmd struct {
	Path        string `name:"path" short:"p" required:"" type:"path" help:"Path to read a file. file must be in (.cert) format."`
	Fingerprint bool   `name:"fingerprint" short:"f" help:"Display SHA-1 and SHA-256 fingerprints."`
	Extensions  bool   `name:"extensions" short:"e" help:"Display X.509 structural extension usage flags (Key Usage, CA flags)."`
	JSON        bool   `name:"json" short:"j" help:"Output certificate details in raw JSON format for scripting."`
}

type certJSONOutput struct {
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	SerialNumber string   `json:"serial_number"`
	SignatureAlg string   `json:"signature_algorithm"`
	KeyAlgo      string   `json:"key_algorithm"`
	KeySize      string   `json:"key_size"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	DNSNames     []string `json:"dns_names,omitempty"`
	IPAddresses  []string `json:"ip_addresses,omitempty"`
	SHA256       string   `json:"sha256_fingerprint,omitempty"`
}

func (icc *InspectCertCmd) Run() error {
	fullPath, err := utils.JoinHomeDir(icc.Path)
	if err != nil {
		return err
	}
	cert, err := utils.ReadCert(fullPath)
	if err != nil {
		return err
	}

	keyAlgo, keySize := getKeyDetails(cert.PublicKey)

	if icc.JSON {
		out := certJSONOutput{
			Subject:      formatDN(cert.Subject),
			Issuer:       formatDN(cert.Issuer),
			SerialNumber: fmt.Sprintf("%x", cert.SerialNumber),
			SignatureAlg: cert.SignatureAlgorithm.String(),
			KeyAlgo:      keyAlgo,
			KeySize:      keySize,
			NotBefore:    cert.NotBefore.Format("2006-01-02 15:04:05 UTC"),
			NotAfter:     cert.NotAfter.Format("2006-01-02 15:04:05 UTC"),
			DNSNames:     cert.DNSNames,
		}
		for _, ip := range cert.IPAddresses {
			out.IPAddresses = append(out.IPAddresses, ip.String())
		}
		if icc.Fingerprint {
			sum256 := sha256.Sum256(cert.Raw)
			out.SHA256 = formatFingerprint(sum256[:])
		}
		jsonBytes, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonBytes))
		return nil
	}

	// --- Default Pretty Print Output ---
	fmt.Println("Certificate Inspection Report")
	fmt.Println(strings.Repeat("─", 50))

	// Print Full Subject Properties
	fmt.Println("  [ Subject Identity ]")
	fmt.Printf("    • Full DN: %s\n", formatDN(cert.Subject))
	if cert.Subject.CommonName != "" {
		fmt.Printf("    • Common Name (CN): %s\n", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) > 0 {
		fmt.Printf("    • Organization (O): %s\n", strings.Join(cert.Subject.Organization, ", "))
	}
	if len(cert.Subject.Country) > 0 {
		fmt.Printf("    • Country (C)     : %s\n", strings.Join(cert.Subject.Country, ", "))
	}

	fmt.Println(strings.Repeat("─", 50))

	// Print Full Issuer Properties
	fmt.Println("  [ Issuer / Signer Identity ]")
	fmt.Printf("    • Full DN: %s\n", formatDN(cert.Issuer))

	fmt.Println(strings.Repeat("─", 50))

	// Print Technical & Crypto Metadata
	fmt.Println("  [ Cryptographic Metadata ]")
	fmt.Printf("    • Serial Number: %x\n", cert.SerialNumber)
	fmt.Printf("    • Signature Alg: %s\n", cert.SignatureAlgorithm)
	fmt.Printf("    • Public Key   : %s (%s)\n", keyAlgo, keySize)

	fmt.Println(strings.Repeat("─", 50))

	// Print Lifecycle Timeline
	fmt.Println("  [ Validity Lifecycle ]")
	fmt.Printf("    • Active From  : %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("    • Expires On   : %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 UTC"))

	fmt.Println(strings.Repeat("─", 50))

	// Print Alternative Target Entities if active
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 {
		fmt.Println("  [ Subject Alternative Names (SAN) ]")
		if len(cert.DNSNames) > 0 {
			fmt.Printf("    • DNS Domains  : %s\n", strings.Join(cert.DNSNames, ", "))
		}
		if len(cert.IPAddresses) > 0 {
			fmt.Printf("    • IP Addresses : %v\n", cert.IPAddresses)
		}
		fmt.Println(strings.Repeat("─", 50))
	}

	// --- Handle --fingerprint flag ---
	if icc.Fingerprint {
		fmt.Println("  [ Certificate Fingerprints ]")
		sum1 := sha1.Sum(cert.Raw)
		sum256 := sha256.Sum256(cert.Raw)
		fmt.Printf("    • SHA-1  : %s\n", formatFingerprint(sum1[:]))
		fmt.Printf("    • SHA-256: %s\n", formatFingerprint(sum256[:]))
		fmt.Println(strings.Repeat("─", 50))
	}

	// --- Handle --extensions flag ---
	if icc.Extensions {
		fmt.Println("  [ Key Usage & Extensions ]")
		fmt.Printf("    • Basic Constraints (CA): %t\n", cert.IsCA)

		// Parse Key Usages
		var usages []string
		usageMap := map[x509.KeyUsage]string{
			x509.KeyUsageDigitalSignature:  "Digital Signature",
			x509.KeyUsageContentCommitment: "Content Commitment",
			x509.KeyUsageKeyEncipherment:   "Key Encipherment",
			x509.KeyUsageDataEncipherment:  "Data Encipherment",
			x509.KeyUsageKeyAgreement:      "Key Agreement",
			x509.KeyUsageCertSign:          "Certificate Signing",
			x509.KeyUsageCRLSign:           "CRL Signing",
		}
		for flag, name := range usageMap {
			if cert.KeyUsage&flag != 0 {
				usages = append(usages, name)
			}
		}
		if len(usages) > 0 {
			fmt.Printf("    • Intended Key Usages   : %s\n", strings.Join(usages, ", "))
		} else {
			fmt.Println("    • Intended Key Usages   : None Specified")
		}
		fmt.Println(strings.Repeat("─", 50))
	}

	return nil
}

type InspectKeyCmd struct {
	Path     string `name:"path" short:"p" required:"" type:"path" help:"Path to read a file. file must be in (.key,.pem) format."`
	Validate bool   `name:"validate" short:"v" help:"Verify the mathematical integrity and validity of the private key."`
	Decrypt  bool   `name:"decrypt" help:"Decrypt the Private key if it is stored as encrypted pem block."`
}

func (ikc *InspectKeyCmd) Run() error {
	usedCipher := false
	if ikc.Decrypt {
		usedCipher = true
	}
	fullPath, err := utils.JoinHomeDir(ikc.Path)
	if err != nil {
		return err
	}
	key, blockType, err := utils.ReadKeyWithBlockType(fullPath, usedCipher)
	if err != nil {
		return err
	}

	fmt.Printf("Key Inspection Report\n")
	fmt.Println(strings.Repeat("─", 55))
	fmt.Printf("  • PEM Block Header Type: %s\n", blockType)

	switch k := key.(type) {

	// ==================== RSA KEY TYPES ====================
	case *rsa.PrivateKey:
		fmt.Println("  • Key Paradigm          : Private (Secret)")
		fmt.Println("  • Cipher Suite          : RSA (Rivest–Shamir–Adleman)")
		fmt.Printf("  • Modulus Bit Size     : %d-bit\n", k.Size()*8)
		fmt.Printf("  • Public Exponent (e)   : %d (0x%x)\n", k.E, k.E)
		fmt.Printf("  • Modulus (N) Fingerprint: %s...\n", truncateHex(k.N.Bytes()))
		fmt.Printf("  • Prime Factor (P) Size : %d bits\n", len(k.Primes[0].Bytes())*8)
		fmt.Printf("  • Prime Factor (Q) Size : %d bits\n", len(k.Primes[1].Bytes())*8)

		// Check internal sanity variables if requested
		if ikc.Validate {
			if err := k.Validate(); err != nil {
				fmt.Printf("  • Validation Status     : Invalid Key! (%s)\n", err.Error())
			} else {
				fmt.Println("  • Validation Status     :  Mathematical Integrity Intact")
			}
		}

	case *rsa.PublicKey:
		fmt.Println("  • Key Paradigm          : Public (Sharable)")
		fmt.Println("  • Cipher Suite          : RSA (Rivest–Shamir–Adleman)")
		fmt.Printf("  • Modulus Bit Size     : %d-bit\n", k.Size()*8)
		fmt.Printf("  • Public Exponent (e)   : %d (0x%x)\n", k.E, k.E)
		fmt.Printf("  • Modulus (N) Fingerprint: %s...\n", truncateHex(k.N.Bytes()))

	// ==================== ECDSA KEY TYPES ====================
	case *ecdsa.PrivateKey:
		fmt.Println("  • Key Paradigm          : Private (Secret)")
		fmt.Println("  • Cipher Suite          : ECDSA (Elliptic Curve Digital Signature)")
		fmt.Printf("  • Chosen Curve Architecture: %s\n", k.Params().Name)
		fmt.Printf("  • Order Limit (N)       : %s...\n", truncateHex(k.Params().N.Bytes()))
		fmt.Printf("  • Private Scalar D      : [Protected / Hidden in Memory]\n")
		pubBytes, err := k.Bytes()
		if err != nil {
			return err
		}
		fmt.Printf("  • Linked Uncompressed Point (X, Y): %s...\n", truncateHex(pubBytes))

		if ikc.Validate {
			if _, err := k.ECDH(); err == nil {
				fmt.Println("  • Validation Status     :  Curve Point Verification Successful")
			} else {
				fmt.Println("  • Validation Status     : Invalid Key! Point is off the curve.")
			}
		}

	case *ecdsa.PublicKey:
		fmt.Println("  • Key Paradigm          : Public (Sharable)")
		fmt.Println("  • Cipher Suite          : ECDSA (Elliptic Curve Digital Signature)")
		fmt.Printf("  • Chosen Curve Architecture: %s\n", k.Params().Name)
		pubBytes, err := k.Bytes()
		if err != nil {
			return err
		}
		fmt.Printf("  • Uncompressed Point (X, Y): %s...\n", truncateHex(pubBytes))

		if ikc.Validate {
			if _, err := k.ECDH(); err == nil {
				fmt.Println("  • Validation Status     :  Curve Point Verification Successful")
			} else {
				fmt.Println("  • Validation Status     : Invalid Key! Point is off the curve.")
			}
		}

	// ==================== ED25519 KEY TYPES ====================
	case ed25519.PrivateKey:
		fmt.Println("  • Key Paradigm          : Private (Secret)")
		fmt.Println("  • Cipher Suite          : Ed25519 (Edwards-curve Digital Signature)")
		fmt.Println("  • Parameters            : Twisted Edwards Curve, Curve25519 base")
		fmt.Printf("  • Key Seed Payload      : %s...\n", truncateHex(k.Seed()))

		pub, ok := k.Public().(ed25519.PublicKey)
		if !ok {
			return errors.New("failed to assert ed25519 private key")
		}
		fmt.Printf("  • Extracted Public Key  : %s\n", hex.EncodeToString(pub))

	case ed25519.PublicKey:
		fmt.Println("  • Key Paradigm          : Public (Sharable)")
		fmt.Println("  • Cipher Suite          : Ed25519 (Edwards-curve Digital Signature)")
		fmt.Println("  • Parameters            : Twisted Edwards Curve, Curve25519 base")
		fmt.Printf("  • Complete Public Point : %s\n", hex.EncodeToString(k))

	default:
		fmt.Printf("  • Structural Type Unknown: %T\n", k)
	}

	fmt.Println(strings.Repeat("─", 55))
	return nil
}

// Helper formatting functions
func formatDN(name pkix.Name) string {
	var parts []string

	if name.CommonName != "" {
		parts = append(parts, fmt.Sprintf("CN=%s", name.CommonName))
	}
	if len(name.Organization) > 0 {
		parts = append(parts, fmt.Sprintf("O=%s", strings.Join(name.Organization, ", ")))
	}
	if len(name.OrganizationalUnit) > 0 {
		parts = append(parts, fmt.Sprintf("OU=%s", strings.Join(name.OrganizationalUnit, ", ")))
	}
	if len(name.Country) > 0 {
		parts = append(parts, fmt.Sprintf("C=%s", strings.Join(name.Country, ", ")))
	}
	if len(name.Province) > 0 {
		parts = append(parts, fmt.Sprintf("ST=%s", strings.Join(name.Province, ", ")))
	}
	if len(name.Locality) > 0 {
		parts = append(parts, fmt.Sprintf("L=%s", strings.Join(name.Locality, ", ")))
	}

	if len(parts) == 0 {
		return "Empty Distinguished Name"
	}
	return strings.Join(parts, ", ")
}

func getKeyDetails(key any) (algoType string, sizeInfo string) {
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

func truncateHex(b []byte) string {
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
func formatFingerprint(b []byte) string {
	var parts []string
	for _, val := range b {
		parts = append(parts, fmt.Sprintf("%02X", val))
	}
	return strings.Join(parts, ":")
}
