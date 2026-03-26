/*
 * Certificate generator
 * Authors: Jorge Alvarez (poro@versprite.com) and Mario Vilas (marito@versprite.com)
 * Released under BSD 3-clause license
 */

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "fetch":
		handleFetch()
	case "clone":
		handleClone()
	case "help", "--help", "-h":
		printUsage()
		os.Exit(0)
	default:
		fmt.Printf("Unknown subcommand: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Certificate generator for Zancudo")
	fmt.Println("Authors: Jorge Alvarez (poro@versprite.com) and Mario Vilas (marito@versprite.com)\n")
	fmt.Println("Usage: gen_certs <subcommand> [options]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  fetch   Fetch a remote certificate and clone it.")
	fmt.Println("          Usage: gen_certs fetch <hostname:port> [flags]")
	fmt.Println("  clone   Clone a local certificate file.")
	fmt.Println("          Usage: gen_certs clone <path_to_cert.pem> [flags]")
	fmt.Println("\nFlags:")
	fmt.Println("  --proxy-hostname <host>   Hostname or IP to issue the new certificate for (instead of the original's).")
	fmt.Println("  --out-cert <path>         Output path for the new certificate (default: \"proxy.crt\" for fetch, \"client.crt\" for clone).")
	fmt.Println("  --out-key <path>          Output path for the new private key (default: \"proxy.key\" for fetch, \"client.key\" for clone).")
	fmt.Println("\nCA Signing Options:")
	fmt.Println("  --ca-cert <path>          Path to the CA certificate file for signing.")
	fmt.Println("  --ca-key <path>           Path to the CA private key file for signing.")
	fmt.Println("  --gen-ca                  Generate a new root CA and use it for signing (saved as ca.crt and ca.key).")
	fmt.Println("\nFlags can also be seen by running the subcommand with -h, e.g.:")
	fmt.Println("  gen_certs fetch -h")
}

func addCASigningFlags(fs *flag.FlagSet) (*string, *string, *bool) {
	caCertPath := fs.String("ca-cert", "", "Path to the CA certificate file for signing.")
	caKeyPath := fs.String("ca-key", "", "Path to the CA private key file for signing.")
	genCA := fs.Bool("gen-ca", false, "Generate a new root CA and use it for signing. The new CA will be saved as ca.crt and ca.key.")
	return caCertPath, caKeyPath, genCA
}

func handleFetch() {
	fetchCmd := flag.NewFlagSet("fetch", flag.ExitOnError)
	proxyHostname := fetchCmd.String("proxy-hostname", "", "Optional: a hostname or IP to issue the new certificate for, instead of the original's.")
	outCert := fetchCmd.String("out-cert", "proxy.crt", "Output path for the new certificate.")
	outKey := fetchCmd.String("out-key", "proxy.key", "Output path for the new private key.")
	caCertPath, caKeyPath, genCA := addCASigningFlags(fetchCmd)
	fetchCmd.Parse(os.Args[2:])

	if fetchCmd.NArg() != 1 {
		log.Fatal("fetch command requires exactly one argument: <hostname:port>")
	}
	remoteAddr := fetchCmd.Arg(0)

	log.Printf("Fetching certificate from %s...", remoteAddr)
	conn, err := tls.Dial("tcp", remoteAddr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Fatalf("Failed to connect to %s: %v", remoteAddr, err)
	}
	defer conn.Close()

	peerCerts := conn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		log.Fatalf("No certificates found on remote server %s", remoteAddr)
	}
	templateCert := peerCerts[0]
	log.Printf("Fetched certificate for '%s'", templateCert.Subject.CommonName)

	caCert, caKey := processCAFlags(*genCA, *caCertPath, *caKeyPath, templateCert)

	generateAndSave(templateCert, *proxyHostname, *outCert, *outKey, caCert, caKey)
}

func handleClone() {
	cloneCmd := flag.NewFlagSet("clone", flag.ExitOnError)
	proxyHostname := cloneCmd.String("proxy-hostname", "", "Optional: a hostname or IP to issue the new certificate for, instead of the original's.")
	outCert := cloneCmd.String("out-cert", "client.crt", "Output path for the new certificate.")
	outKey := cloneCmd.String("out-key", "client.key", "Output path for the new private key.")
	caCertPath, caKeyPath, genCA := addCASigningFlags(cloneCmd)
	cloneCmd.Parse(os.Args[2:])

	if cloneCmd.NArg() != 1 {
		log.Fatal("clone command requires exactly one argument: <path_to_cert.pem>")
	}
	certPath := cloneCmd.Arg(0)

	log.Printf("Reading certificate from %s...", certPath)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		log.Fatalf("Failed to read certificate file: %v", err)
	}

	pemBlock, _ := pem.Decode(certPEM)
	if pemBlock == nil || pemBlock.Type != "CERTIFICATE" {
		log.Fatal("Failed to decode PEM block containing certificate")
	}

	templateCert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}
	log.Printf("Parsed certificate for '%s'", templateCert.Subject.CommonName)

	caCert, caKey := processCAFlags(*genCA, *caCertPath, *caKeyPath, templateCert)

	generateAndSave(templateCert, *proxyHostname, *outCert, *outKey, caCert, caKey)
}

func processCAFlags(genCA bool, caCertPath, caKeyPath string, leafCertAsTemplate *x509.Certificate) (*x509.Certificate, *rsa.PrivateKey) {
	if genCA {
		if caCertPath != "" || caKeyPath != "" {
			log.Fatal("--gen-ca cannot be used with --ca-cert or --ca-key")
		}
		log.Println("Generating new root CA...")
		caCert, caKey, err := generateCARoot(leafCertAsTemplate)
		if err != nil {
			log.Fatalf("Failed to generate root CA: %v", err)
		}
		if err := saveCertAndKey(caCert, caKey, "ca.crt", "ca.key"); err != nil {
			log.Fatalf("Failed to save new root CA: %v", err)
		}
		log.Println("New root CA saved to ca.crt and ca.key.")
		return caCert, caKey
	}

	if caCertPath != "" && caKeyPath != "" {
		log.Printf("Loading CA from %s and %s...", caCertPath, caKeyPath)
		caCert, caKey, err := loadCA(caCertPath, caKeyPath)
		if err != nil {
			log.Fatalf("Failed to load CA: %v", err)
		}
		log.Println("CA loaded successfully.")
		return caCert, caKey
	}

	if caCertPath != "" && caKeyPath == "" {
		log.Printf("Only CA certificate provided. Loading %s as a template to generate a new CA.", caCertPath)
		caTemplate, err := loadCert(caCertPath)
		if err != nil {
			log.Fatalf("Failed to load CA certificate template: %v", err)
		}

		log.Println("Generating new root CA based on provided template...")
		// Use the loaded cert's issuer as a template. If it's a self-signed root, issuer will equal subject.
		caCert, caKey, err := generateCARoot(caTemplate)
		if err != nil {
			log.Fatalf("Failed to generate root CA from template: %v", err)
		}
		if err := saveCertAndKey(caCert, caKey, "ca.crt", "ca.key"); err != nil {
			log.Fatalf("Failed to save new root CA: %v", err)
		}
		log.Println("New root CA (based on template) saved to ca.crt and ca.key.")
		return caCert, caKey
	}

	if caCertPath == "" && caKeyPath != "" {
		log.Fatal("--ca-key cannot be used without --ca-cert")
	}

	return nil, nil // No CA, will self-sign
}

func generateAndSave(templateCert *x509.Certificate, proxyHostname, outCert, outKey string, caCert *x509.Certificate, caKey *rsa.PrivateKey) {
	log.Println("Generating new certificate and private key...")
	newCert, newKey, err := generateSignedCertificate(templateCert, proxyHostname, caCert, caKey)
	if err != nil {
		log.Fatalf("Could not generate certificate: %v", err)
	}
	log.Println("Certificate and key generated.")

	log.Printf("Saving certificate to %s and key to %s...", outCert, outKey)
	if err := saveCertAndKey(newCert, newKey, outCert, outKey); err != nil {
		log.Fatalf("Could not save files: %v", err)
	}
	log.Println("Files saved successfully.")
}

func generateSignedCertificate(template *x509.Certificate, proxyHostname string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create a new template and explicitly copy the fields we want to preserve.
	// This is more robust than a shallow struct copy.
	newTemplate := x509.Certificate{
		Subject:            template.Subject,
		DNSNames:           template.DNSNames,
		IPAddresses:        template.IPAddresses,
		EmailAddresses:     template.EmailAddresses,
		KeyUsage:           template.KeyUsage,
		ExtKeyUsage:        template.ExtKeyUsage,
		UnknownExtKeyUsage: template.UnknownExtKeyUsage,

		SerialNumber:       serialNumber,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(1, 0, 0),
		PublicKeyAlgorithm: x509.RSA,
	}

	// Replace hostname if requested
	if proxyHostname != "" {
		if ip := net.ParseIP(proxyHostname); ip != nil {
			newTemplate.IPAddresses = []net.IP{ip}
			newTemplate.DNSNames = nil
		} else {
			newTemplate.DNSNames = []string{proxyHostname}
			newTemplate.IPAddresses = nil
		}
		newTemplate.Subject.CommonName = proxyHostname
	}

	var signerCert *x509.Certificate
	var signerKey interface{}

	if caCert != nil && caKey != nil {
		// Sign with the provided CA
		signerCert = caCert
		signerKey = caKey
		newTemplate.Issuer = signerCert.Subject
	} else {
		// Self-sign: the template is its own issuer.
		// The public key in the template must match the private key used for signing.
		newTemplate.PublicKey = &priv.PublicKey
		newTemplate.PublicKeyAlgorithm = x509.RSA
		signerCert = &newTemplate
		signerKey = priv
		newTemplate.Issuer = newTemplate.Subject
	}

	newTemplate.IsCA = false
	newTemplate.BasicConstraintsValid = true

	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &newTemplate, signerCert, &priv.PublicKey, signerKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	newCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	return newCert, priv, nil
}

func saveCertAndKey(cert *x509.Certificate, key *rsa.PrivateKey, certPath, keyPath string) error {
	// Save certificate
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", certPath, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return fmt.Errorf("failed to write data to %s: %w", certPath, err)
	}
	if err := certOut.Close(); err != nil {
		return fmt.Errorf("error closing %s: %w", certPath, err)
	}

	// Save private key
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", keyPath, err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("unable to marshal private key: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write data to %s: %w", keyPath, err)
	}
	if err := keyOut.Close(); err != nil {
		return fmt.Errorf("error closing %s: %w", keyPath, err)
	}

	return nil
}

func generateCARoot(leafCertAsTemplate *x509.Certificate) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key for CA: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number for CA: %w", err)
	}

	newTemplate := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	if leafCertAsTemplate != nil {
		log.Println("Cloning issuer subject from leaf certificate for new CA...")
		// The `Names` field is ignored during creation; `ExtraNames` is used.
		// By copying all attributes here, we ensure they are all preserved.
		newTemplate.Subject.ExtraNames = leafCertAsTemplate.Issuer.Names
	} else {
		log.Println("Creating default CA certificate...")
		newTemplate.Subject = pkix.Name{
			Organization: []string{"MQTT Proxy Generated CA"},
			CommonName:   "MQTT Proxy Root CA",
		}
	}

	newTemplate.Issuer = newTemplate.Subject // self-sign
	newTemplate.PublicKey = &priv.PublicKey
	newTemplate.PublicKeyAlgorithm = x509.RSA

	derBytes, err := x509.CreateCertificate(rand.Reader, &newTemplate, &newTemplate, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse generated CA certificate: %w", err)
	}

	return cert, priv, nil
}

func loadCA(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA cert file %s: %w", certPath, err)
	}
	pemBlock, _ := pem.Decode(certPEM)
	if pemBlock == nil || pemBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to decode PEM block containing CA certificate")
	}
	caCert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA key file %s: %w", keyPath, err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return nil, nil, fmt.Errorf("failed to decode PEM block for CA private key")
	}
	priv, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}
	caKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA private key is not of type RSA")
	}

	return caCert, caKey, nil
}

func loadCert(certPath string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert file %s: %w", certPath, err)
	}
	pemBlock, _ := pem.Decode(certPEM)
	if pemBlock == nil || pemBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}
