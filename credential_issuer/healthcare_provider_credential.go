package credential_issuer

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-didx509-toolkit/x509_cert"
)

// HealthcareProviderCredentialType holds the name of the HealthcareProviderCredential type.
var HealthcareProviderCredentialType = ssi.MustParseURI("HealthcareProviderCredential")

// HealthcareProviderCredentialContext is the JSON-LD context URI for the HealthcareProviderCredential,
// derived from the credential type. The AORTA-on-FHIR spec models this as a deployment-specific
// <aorta-gbc-base>/gbc/context/v1; the toolkit standardizes on the shared vzvz.nl context.
var HealthcareProviderCredentialContext = ssi.MustParseURI("https://vzvz.nl/credentials/v1")

// uraNamingSystem is the FHIR NamingSystem URI for the URA identifier.
const uraNamingSystem = "http://fhir.nl/fhir/NamingSystem/ura"

// IssueHealthcareProviderCredential issues a HealthcareProviderCredential as a JWT VC, signed with the given key
// and using a did:x509 issuer derived from the chain and caFingerprintCert. Shape per the AORTA-on-FHIR
// HealthcareProviderCredential specification. The URA and organization name being attested to are parsed from
// the signing certificate: URA from the SAN otherName UZI value, name from the subject's O (Organization) attribute.
func IssueHealthcareProviderCredential(chain []*x509.Certificate, caFingerprintCert *x509.Certificate, key crypto.Signer, subjectDID string, optionFns ...Option) (*vc.VerifiableCredential, error) {
	issuer, err := resolveIssuer(chain, caFingerprintCert, resolveOptions(optionFns...))
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
	template := HealthcareProviderTemplate(*issuer, signingCert.NotAfter, subjectDID, ura, organizationName)
	// RS256: UZI/PKIoverheid certificates are RSA and the AORTA ecosystem expects
	// RS256 (RSA PKCS#1 v1.5), not PS256 (RSA-PSS).
	return IssueCredential(template, chain, issuer, signingCert, key, jwa.RS256)
}

// HealthcareProviderTemplate builds a HealthcareProviderCredential template per the AORTA-on-FHIR spec:
// credentialSubject has @type HealthcareProvider, a single identifier object (@type Identifier, URA system+value)
// and the organization name.
func HealthcareProviderTemplate(issuerDID did.DID, expirationDate time.Time, subjectDID, ura, organizationName string) vc.VerifiableCredential {
	iat := time.Now()
	id := did.DIDURL{
		DID:      issuerDID,
		Fragment: uuid.NewString(),
	}.URI()
	return vc.VerifiableCredential{
		Issuer: issuerDID.URI(),
		Context: []ssi.URI{
			ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"),
			HealthcareProviderCredentialContext,
		},
		Type:           []ssi.URI{ssi.MustParseURI("VerifiableCredential"), HealthcareProviderCredentialType},
		ID:             &id,
		IssuanceDate:   iat,
		ExpirationDate: &expirationDate,
		CredentialSubject: []map[string]any{{
			"id":    subjectDID,
			"@type": "HealthcareProvider",
			"identifier": map[string]any{
				"@type":  "Identifier",
				"system": uraNamingSystem,
				"value":  ura,
			},
			"name": organizationName,
		}},
	}
}
