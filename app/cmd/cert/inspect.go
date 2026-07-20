package cert

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

type InspectCmd struct {
	SerialNumber string `name:"sn" xor:"own" help:"Serial Number of the Certificate."`
	CommonName   string `name:"cn" xor:"own" help:"Common Name of the Certificate."`
	Fingerprint  bool   `name:"fingerprint" short:"f" help:"Display SHA-1 and SHA-256 fingerprints."`
	Usage        bool   `name:"key-usages" short:"u" help:"Display X.509 structural key usage flags."`
	Extensions   bool   `name:"extensions" short:"e" help:"Display X.509 structural extension usage flags."`
	JSON         bool   `name:"json" short:"j" help:"Output certificate details in raw JSON format for scripting."`
}

type JSONOutput struct {
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
	IsCA         bool     `json:"is_ca"`
	KeyUsages    []string `json:"key_usages,omitempty"`
	ExtKeyUsages []string `json:"ext_key_usages,omitempty"`
	SHA1         string   `json:"sha1_fingerprint,omitempty"`
	SHA256       string   `json:"sha256_fingerprint,omitempty"`
}

func (ic *InspectCmd) Run(ctx context.Context, query base.Querier) error {
	cert, err := ic.fetchCertificate(ctx, query)
	if err != nil {
		return err
	}

	keyAlgo, keySize := utils.GetKeyDetails(cert.PublicKey)

	if ic.JSON {
		return ic.outputJSON(cert, keyAlgo, keySize)
	}

	return ic.outputPretty(cert, keyAlgo, keySize)
}

func (icc *InspectCmd) fetchCertificate(ctx context.Context, query base.Querier) (*x509.Certificate, error) {
	var cert *x509.Certificate

	if icc.SerialNumber != "" && icc.CommonName == "" {
		dbCert, err := query.GetCertificateBySN(ctx, icc.SerialNumber)
		if err != nil {
			return nil, fmt.Errorf("failed to get Certificate: %w", err)
		}
		cert, err = utils.ParseCertificate([]byte(dbCert.CertificatePem))
		if err != nil {
			return nil, err
		}
	} else if icc.SerialNumber == "" && icc.CommonName != "" {
		dbCert, err := query.GetCertificateByCN(ctx, icc.CommonName)
		if err != nil {
			return nil, fmt.Errorf("failed to get Certificate: %w", err)
		}
		cert, err = utils.ParseCertificate([]byte(dbCert.CertificatePem))
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("exactly one flag (--sn or --cn) must be provided")
	}
	return cert, nil
}

func (ic *InspectCmd) outputJSON(cert *x509.Certificate, keyAlgo, keySize string) error {
	out := JSONOutput{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: fmt.Sprintf("%x", cert.SerialNumber),
		SignatureAlg: cert.SignatureAlgorithm.String(),
		KeyAlgo:      keyAlgo,
		KeySize:      keySize,
		NotBefore:    cert.NotBefore.Format("2006-01-02 15:04:05 UTC"),
		NotAfter:     cert.NotAfter.Format("2006-01-02 15:04:05 UTC"),
		DNSNames:     cert.DNSNames,
		IsCA:         cert.IsCA,
	}

	for _, ip := range cert.IPAddresses {
		out.IPAddresses = append(out.IPAddresses, ip.String())
	}

	if ic.Usage {
		out.KeyUsages = utils.MarshalKeyUsage(cert.KeyUsage)
	}

	if ic.Extensions {
		out.ExtKeyUsages = utils.MarshalExtKeyUsages(cert.ExtKeyUsage)
	}

	if ic.Fingerprint {
		sum1 := sha1.Sum(cert.Raw)
		sum256 := sha256.Sum256(cert.Raw)
		out.SHA1 = utils.FormatFingerprint(sum1[:])
		out.SHA256 = utils.FormatFingerprint(sum256[:])
	}

	jsonBytes, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonBytes))
	return nil
}

func (ic *InspectCmd) outputPretty(cert *x509.Certificate, keyAlgo, keySize string) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "Certificate Inspection Report")
	fmt.Fprintln(w, strings.Repeat("─", 60))

	// Subject Identity
	fmt.Fprintln(w, "[ Subject Identity ]")
	fmt.Fprintf(w, "  Full DN:\t%s\n", cert.Subject.String())
	if cert.Subject.CommonName != "" {
		fmt.Fprintf(w, "  Common Name (CN):\t%s\n", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) > 0 {
		fmt.Fprintf(w, "  Organization (O):\t%s\n", strings.Join(cert.Subject.Organization, ", "))
	}
	if len(cert.Subject.Country) > 0 {
		fmt.Fprintf(w, "  Country (C):\t%s\n", strings.Join(cert.Subject.Country, ", "))
	}

	fmt.Fprintln(w, strings.Repeat("─", 60))

	// Issuer Identity
	fmt.Fprintln(w, "[ Issuer / Signer Identity ]")
	fmt.Fprintf(w, "  Full DN:\t%s\n", cert.Issuer.String())

	fmt.Fprintln(w, strings.Repeat("─", 60))

	// Cryptographic Metadata
	fmt.Fprintln(w, "[ Cryptographic Metadata ]")
	fmt.Fprintf(w, "  Serial Number:\t%x\n", cert.SerialNumber)
	fmt.Fprintf(w, "  Signature Alg:\t%s\n", cert.SignatureAlgorithm)
	fmt.Fprintf(w, "  Public Key:\t%s (%s)\n", keyAlgo, keySize)

	fmt.Fprintln(w, strings.Repeat("─", 60))

	// Validity Lifecycle
	fmt.Fprintln(w, "[ Validity Lifecycle ]")
	fmt.Fprintf(w, "  Active From:\t%s\n", cert.NotBefore.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(w, "  Expires On:\t%s\n", cert.NotAfter.Format("2006-01-02 15:04:05 UTC"))

	fmt.Fprintln(w, strings.Repeat("─", 60))

	// Subject Alternative Names (SAN)
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 {
		fmt.Fprintln(w, "[ Subject Alternative Names (SAN) ]")
		if len(cert.DNSNames) > 0 {
			fmt.Fprintf(w, "  DNS Domains:\t%s\n", strings.Join(cert.DNSNames, ", "))
		}
		if len(cert.IPAddresses) > 0 {
			ips := make([]string, len(cert.IPAddresses))
			for i, ip := range cert.IPAddresses {
				ips[i] = ip.String()
			}
			fmt.Fprintf(w, "  IP Addresses:\t%s\n", strings.Join(ips, ", "))
		}
		fmt.Fprintln(w, strings.Repeat("─", 60))
	}

	// Handle --fingerprint flag
	if ic.Fingerprint {
		fmt.Fprintln(w, "[ Certificate Fingerprints ]")
		sum1 := sha1.Sum(cert.Raw)
		sum256 := sha256.Sum256(cert.Raw)
		fmt.Fprintf(w, "  SHA-1:\t%s\n", utils.FormatFingerprint(sum1[:]))
		fmt.Fprintf(w, "  SHA-256:\t%s\n", utils.FormatFingerprint(sum256[:]))
		fmt.Fprintln(w, strings.Repeat("─", 60))
	}

	// Handle --usage flag
	if ic.Usage {
		fmt.Fprintln(w, "[ Key Usage ]")
		usages := utils.MarshalKeyUsage(cert.KeyUsage)
		if len(usages) > 0 {
			fmt.Fprintf(w, "  Intended Key Usages:\t%s\n", strings.Join(usages, ", "))
		} else {
			fmt.Fprintln(w, "  Intended Key Usages:\tNone Specified")
		}
		fmt.Fprintln(w, strings.Repeat("─", 60))
	}

	// Handle --extensions flag
	if ic.Extensions {
		fmt.Fprintln(w, "[ Extended Key Usage ]")
		usages := utils.MarshalExtKeyUsages(cert.ExtKeyUsage)
		if len(usages) > 0 {
			fmt.Fprintf(w, "  Extended Key Usages:\t%s\n", strings.Join(usages, ", "))
		} else {
			fmt.Fprintln(w, "  Extended Key Usages:\tNone Specified")
		}
		fmt.Fprintln(w, strings.Repeat("─", 60))
	}

	// CA Flag Fallback
	if !ic.Usage && !ic.Extensions {
		fmt.Fprintln(w, "[ Basic Constraints ]")
		fmt.Fprintf(w, "  Is CA Certificate:\t%t\n", cert.IsCA)
		fmt.Fprintln(w, strings.Repeat("─", 60))
	}

	return w.Flush()
}
