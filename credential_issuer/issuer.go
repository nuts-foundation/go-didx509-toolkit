package credential_issuer

import (
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"github.com/nuts-foundation/go-didx509-toolkit/internal"
	"time"

	"github.com/nuts-foundation/go-did/did"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-didx509-toolkit/did_x509"
	"github.com/nuts-foundation/go-didx509-toolkit/x509_cert"
)

// CredentialType holds the name of the X.509 credential type.
var CredentialType = ssi.MustParseURI("X509Credential")

// issueOptions contains values for options for issuing a UZI VC.
type issueOptions struct {
	subjectAttributes []x509_cert.SubjectTypeName
	sanAttributes     []x509_cert.SanTypeName
}

// Option is an interface for a function in the options pattern.
type Option = func(*issueOptions)

var defaultIssueOptions = &issueOptions{
	sanAttributes:     []x509_cert.SanTypeName{x509_cert.SanTypeOtherName},
	subjectAttributes: []x509_cert.SubjectTypeName{},
}

func Issue(chain []*x509.Certificate, caFingerprintCert *x509.Certificate, key *rsa.PrivateKey, subject string, optionFns ...Option) (*vc.VerifiableCredential, error) {
	options := *defaultIssueOptions
	for _, fn := range optionFns {
		fn(&options)
	}

	// Sanity check: make sure caFingerprintCert is in the chain
	caFingerprintCertPresent := false
	for _, curr := range chain {
		if curr.Equal(caFingerprintCert) {
			caFingerprintCertPresent = true
			break
		}
	}
	if !caFingerprintCertPresent {
		return nil, errors.New("caFingerprintCert is not in the chain")
	}

	issuer, err := did_x509.CreateDid(chain[0], caFingerprintCert, options.subjectAttributes, options.sanAttributes...)
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
	template, err := buildCredential(*issuer, signingCert.NotAfter, sanValues, subjectTypes, subject)
	if err != nil {
		return nil, err
	}
	return vc.CreateJWTVerifiableCredential(context.Background(), *template, func(ctx context.Context, claims map[string]interface{}, headers map[string]interface{}) (string, error) {
		token, err := convertClaims(claims)
		if err != nil {
			return "", err
		}
		hdrs, err := convertHeaders(headers)
		if err != nil {
			return "", err
		}

		if hdrs.KeyID() == "" {
			err := hdrs.Set("kid", issuer.String()+"#0")
			if err != nil {
				return "", err
			}
		}

		// x5c
		serializedCert, err := marshalChain(chain...)
		if err != nil {
			return "", err
		}
		err = hdrs.Set("x5c", serializedCert)
		if err != nil {
			return "", err
		}

		// x5t
		hashSha1 := sha1.Sum(signingCert.Raw)
		err = hdrs.Set("x5t", base64.RawURLEncoding.EncodeToString(hashSha1[:]))
		if err != nil {
			return "", err
		}

		sign, err := jwt.Sign(token, jwt.WithKey(jwa.PS256, *key, jws.WithProtectedHeaders(hdrs)))
		return string(sign), err
	})
}

// SubjectAttributes sets the subject attributes to include in the DID and VC.
func SubjectAttributes(attributes ...x509_cert.SubjectTypeName) Option {
	return func(o *issueOptions) {
		o.subjectAttributes = attributes
	}
}

// SANAttributes sets whether to include the SAN permanent identifier in the DID and VC.
func SANAttributes(attributes ...x509_cert.SanTypeName) Option {
	return func(o *issueOptions) {
		o.sanAttributes = attributes
	}
}

// marshalChain converts a slice of x509.Certificate instances to a cert.Chain, encoding each certificate as PEM.
// It returns the PEM-encoded cert.Chain and an error if the encoding or header fixation fails.
func marshalChain(certificates ...*x509.Certificate) (*cert.Chain, error) {
	chainPems := &cert.Chain{}
	for _, certificate := range certificates {
		err := chainPems.Add([]byte(base64.StdEncoding.EncodeToString(certificate.Raw)))
		if err != nil {
			return nil, err
		}
	}
	headers, err := internal.FixChainHeaders(chainPems)
	return headers, err
}

// convertClaims converts a map of claims to a JWT token.
func convertClaims(claims map[string]interface{}) (jwt.Token, error) {
	t := jwt.New()
	for k, v := range claims {
		if err := t.Set(k, v); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// convertHeaders converts a map of headers to jws.Headers, returning an error if any header fails to set.
func convertHeaders(headers map[string]interface{}) (jws.Headers, error) {
	hdr := jws.NewHeaders()

	for k, v := range headers {
		if err := hdr.Set(k, v); err != nil {
			return nil, err
		}
	}
	return hdr, nil
}

func buildCredential(issuerDID did.DID, expirationDate time.Time, otherNameValues []*x509_cert.PolicyValue, subjectTypes []*x509_cert.PolicyValue, subjectDID string) (*vc.VerifiableCredential, error) {
	iat := time.Now()
	subject := map[string]interface{}{
		"id": subjectDID,
	}
	addSubjectPolicyProperty := func(policy string, propKey string, propValue string) {
		policyProps, ok := subject[policy].(map[string]interface{})
		if !ok {
			policyProps = make(map[string]interface{})
			subject[policy] = policyProps
		}
		policyProps[propKey] = propValue
	}
	for _, otherNameValue := range otherNameValues {
		addSubjectPolicyProperty(otherNameValue.PolicyType, otherNameValue.Type, otherNameValue.Value)
	}

	for _, subjectType := range subjectTypes {
		addSubjectPolicyProperty(subjectType.PolicyType, subjectType.Type, subjectType.Value)
	}

	id := did.DIDURL{
		DID:      issuerDID,
		Fragment: uuid.NewString(),
	}.URI()
	return &vc.VerifiableCredential{
		Issuer:            issuerDID.URI(),
		Context:           []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")},
		Type:              []ssi.URI{ssi.MustParseURI("VerifiableCredential"), CredentialType},
		ID:                &id,
		IssuanceDate:      iat,
		ExpirationDate:    &expirationDate,
		CredentialSubject: []interface{}{subject},
	}, nil
}
