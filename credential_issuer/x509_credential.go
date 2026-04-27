package credential_issuer

import (
	"crypto"
	"crypto/x509"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-didx509-toolkit/x509_cert"
)

func IssueX509Credential(chain []*x509.Certificate, caFingerprintCert *x509.Certificate, key crypto.Signer, subject string, optionFns ...Option) (*vc.VerifiableCredential, error) {
	options := resolveOptions(optionFns...)
	issuer, err := resolveIssuer(chain, caFingerprintCert, options)
	if err != nil {
		return nil, err
	}
	// signing cert is at the start of the chain
	signingCert := chain[0]
	sanValues, err := x509_cert.SelectSanTypes(signingCert, options.sanAttributes...)
	if err != nil {
		return nil, err
	}

	subjectTypes, err := x509_cert.SelectSubjectTypes(signingCert, options.subjectAttributes...)
	if err != nil {
		return nil, err
	}
	template := Template(*issuer, signingCert.NotAfter, sanValues, subjectTypes, subject)
	return IssueCredential(template, chain, issuer, signingCert, key, jwa.PS256)
}
