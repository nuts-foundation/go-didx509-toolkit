package main

import (
	"bufio"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/alecthomas/kong"
	"github.com/nuts-foundation/go-didx509-toolkit/credential_issuer"
	"github.com/nuts-foundation/go-didx509-toolkit/internal"
	"github.com/nuts-foundation/go-didx509-toolkit/x509_cert"
	"os"
)

type VC struct {
	CertificateFile string `arg:"" name:"certificate_file" help:"PEM file containing the full certificate chain." type:"existingfile"`
	SigningKeyFile  string `arg:"" name:"signing_key_file" help:"PEM file containing the private key of the leaf certificate." type:"existingfile"`
	// CAFingerprintDN specifies the subject DN of the certificate that should be used as did:x509 ca-fingerprint property.
	CAFingerprintDN   string                      `arg:"" short:"c" name:"ca_fingerprint_dn" help:"The full subject DN (distinguished name) of the CA certificate to be used as ca-fingerprint in the X.509 DID. The certificate must be present in the chain specified by certificate_file."`
	SubjectDID        string                      `arg:"" name:"subject_did" help:"The subject DID of the Verifiable Credential."`
	SubjectAttributes []x509_cert.SubjectTypeName `short:"s" name:"subject_attr" help:"List of X.509 subject attributes to include in the Verifiable Credential." default:"O,L"`
	SANAttributes     []string                    `short:"a" help:"List of SAN attributes to include in the Verifiable Credential (options: 'otherName', 'permanentIdentifier.assigner', 'permanentIdentifier.value')." default:"otherName"`
}

var _ error = InvalidCAFingerprintDNError{}

type InvalidCAFingerprintDNError struct {
	Candidates []string
}

func (i InvalidCAFingerprintDNError) Error() string {
	return "ca-fingerprint certificate not found in chain"
}

var CLI struct {
	Version string `help:"Show version."`
	Vc      VC     `cmd:"" help:"Create a new VC."`
}

func main() {
	cli := &CLI
	parser, err := kong.New(cli)
	if err != nil {
		panic(err)
	}
	ctx, err := parser.Parse(os.Args[1:])
	if err != nil {
		parser.FatalIfErrorf(err)
	}

	switch ctx.Command() {
	case "vc <certificate_file> <signing_key_file> <ca_fingerprint_dn> <subject_did>":
		vc := cli.Vc
		jwt, err := issueVc(vc)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err.Error())
			var invalidCAFingerprintDNErr InvalidCAFingerprintDNError
			if errors.As(err, &invalidCAFingerprintDNErr) {
				_, _ = fmt.Fprintln(os.Stderr, "Candidates:")
				for _, candidate := range invalidCAFingerprintDNErr.Candidates {
					_, _ = fmt.Fprintln(os.Stderr, "  "+candidate)
				}
			}
			os.Exit(-1)
			return
		}
		err = printLineAndFlush(jwt)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(-1)
		}
	default:
		_, _ = fmt.Fprintln(os.Stderr, "Unknown command")
		os.Exit(-1)
	}
}

// printLineAndFlush writes a JWT (JSON Web Token) to the standard output and flushes the buffered writer.
func printLineAndFlush(jwt string) error {
	f := bufio.NewWriter(os.Stdout)
	// Make sure to flush
	defer func(f *bufio.Writer) {
		_ = f.Flush()
	}(f)
	// Write the JWT
	_, err := f.WriteString(jwt + "\n")
	return err
}

func issueVc(vc VC) (string, error) {
	certFileData, err := os.ReadFile(vc.CertificateFile)
	if err != nil {
		return "", fmt.Errorf("failed to read certificate file: %w", err)
	}
	certs, err := internal.ParseCertificatesFromPEM(certFileData)
	if err != nil {
		return "", err
	}
	chain, err := internal.ParseCertificateChain(certs)
	if err != nil {
		return "", err
	}

	// Select ca-fingerprint certificate
	var caFingerprintCert *x509.Certificate
	var candidates []string
	for _, candidate := range chain {
		if candidate.Subject.String() == vc.CAFingerprintDN {
			caFingerprintCert = candidate
			break
		}
		candidates = append(candidates, candidate.Subject.String())
	}
	if caFingerprintCert == nil {
		return "", InvalidCAFingerprintDNError{Candidates: candidates}
	}

	keyFileData, err := os.ReadFile(vc.SigningKeyFile)
	if err != nil {
		return "", fmt.Errorf("failed to read key file: %w", err)
	}
	key, err := internal.ParseRSAPrivateKeyFromPEM(keyFileData)
	if err != nil {
		return "", err
	}

	credential, err := credential_issuer.Issue(chain, caFingerprintCert, key, vc.SubjectDID,
		credential_issuer.SubjectAttributes(vc.SubjectAttributes...),
		credential_issuer.SANAttributes(vc.SANAttributes...),
	)

	if err != nil {
		return "", err
	}

	return credential.Raw(), nil
}
