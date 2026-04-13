package credential_issuer

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-didx509-toolkit/x509_cert"
)

// HealthcareOrganizationCredentialType holds the name of the HealthcareOrganizationCredential type.
var HealthcareOrganizationCredentialType = ssi.MustParseURI("HealthcareOrganizationCredential")

// HealthcareOrganizationCredentialContext is the JSON-LD context URI for the HealthcareOrganizationCredential.
var HealthcareOrganizationCredentialContext = ssi.MustParseURI("https://vzvz.nl/credentials/v1")

// IssueHealthcareOrganizationCredential issues a HealthcareOrganizationCredential as a JWT VC, signed with the given key
// and using a did:x509 issuer derived from the chain and caFingerprintCert.
// The URA and organization name of the healthcare organization being attested to are parsed from the signing certificate:
// - URA is extracted from the SAN otherName UZI value
// - organization name is taken from the subject's O (Organization) attribute
func IssueHealthcareOrganizationCredential(chain []*x509.Certificate, caFingerprintCert *x509.Certificate, key crypto.Signer, subjectDID string, optionFns ...Option) (*vc.VerifiableCredential, error) {
	issuer, _, err := resolveIssuer(chain, caFingerprintCert, optionFns...)
	if err != nil {
		return nil, err
	}
	signingCert := chain[0]
	ura, err := ExtractURA(signingCert)
	if err != nil {
		return nil, err
	}
	subjectTypes, err := x509_cert.FindSubjectTypes(signingCert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subject attributes: %w", err)
	}
	var organizationName string
	for _, s := range subjectTypes {
		if s.Type == x509_cert.SubjectTypeOrganization {
			organizationName = s.Value
			break
		}
	}
	if organizationName == "" {
		return nil, fmt.Errorf("certificate subject does not contain an Organization (O) attribute")
	}
	template := HealthcareOrganizationTemplate(*issuer, signingCert.NotAfter, subjectDID, ura, organizationName)
	return IssueCredential(template, chain, issuer, signingCert, key, jwa.PS256)
}

// ExtractURA extracts the URA (Unieke Registratie Aanduiding) from the UZI otherName SAN value of the certificate.
// The UZI otherName value follows the format: 2.16.528.1.1007.99.2110-1-<UZI>-S-<URA>-<AGB>, where URA is the 5th dash-separated part.
func ExtractURA(cert *x509.Certificate) (string, error) {
	sanTypes, err := x509_cert.FindSanTypes(cert)
	if err != nil {
		return "", fmt.Errorf("failed to parse SAN attributes: %w", err)
	}
	for _, sanType := range sanTypes {
		if sanType.Type != x509_cert.SanTypeOtherName {
			continue
		}
		parts := strings.Split(sanType.Value, "-")
		if len(parts) < 5 {
			return "", fmt.Errorf("unexpected UZI otherName format: %s", sanType.Value)
		}
		ura := parts[4]
		if ura == "" {
			return "", fmt.Errorf("URA is empty in UZI otherName: %s", sanType.Value)
		}
		return ura, nil
	}
	return "", fmt.Errorf("no otherName SAN attribute found in certificate")
}


// HealthcareOrganizationTemplate builds a HealthcareOrganizationCredential template with the given subject data.
func HealthcareOrganizationTemplate(issuerDID did.DID, expirationDate time.Time, subjectDID, ura, organizationName string) vc.VerifiableCredential {
	iat := time.Now()
	id := did.DIDURL{
		DID:      issuerDID,
		Fragment: uuid.NewString(),
	}.URI()
	return vc.VerifiableCredential{
		Issuer: issuerDID.URI(),
		Context: []ssi.URI{
			ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"),
			HealthcareOrganizationCredentialContext,
		},
		Type:           []ssi.URI{ssi.MustParseURI("VerifiableCredential"), HealthcareOrganizationCredentialType},
		ID:             &id,
		IssuanceDate:   iat,
		ExpirationDate: &expirationDate,
		CredentialSubject: []map[string]any{{
			"id": subjectDID,
			"organization": map[string]any{
				"ura":  ura,
				"name": organizationName,
			},
		}},
	}
}
