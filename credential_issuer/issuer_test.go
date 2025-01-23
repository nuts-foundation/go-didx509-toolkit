package credential_issuer

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/nuts-foundation/go-didx509-toolkit/internal"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-didx509-toolkit/x509_cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildX509Credential(t *testing.T) {
	allCerts, err := internal.ParseCertificatesFromPEM([]byte(internal.TestCertificateChain))
	require.NoError(t, err)
	chain, err := internal.ParseCertificateChain(allCerts)
	require.NoError(t, err)

	privKey, err := internal.ParseRSAPrivateKeyFromPEM([]byte(internal.TestSigningKey))
	require.NoError(t, err, "failed to read signing key")

	type inFn = func(t *testing.T) ([]*x509.Certificate, *rsa.PrivateKey, string)

	defaultIn := func(t *testing.T) ([]*x509.Certificate, *rsa.PrivateKey, string) {

		return chain, privKey, "did:example:123"
	}

	tests := []struct {
		name      string
		in        inFn
		errorText string
	}{
		{
			name:      "ok - valid chain",
			in:        defaultIn,
			errorText: "",
		},
		{
			name: "nok - invalid signing certificate 2",
			in: func(t *testing.T) ([]*x509.Certificate, *rsa.PrivateKey, string) {
				certs, privKey, didStr := defaultIn(t)

				certs[0].ExtraExtensions = make([]pkix.Extension, 0)
				certs[0].Extensions = make([]pkix.Extension, 0)
				return certs, privKey, didStr
			},
			errorText: "no values found in the SAN attributes, please check if the certificate is an UZI Server Certificate",
		},
		{
			name: "nok - empty cert in chain",
			in: func(t *testing.T) ([]*x509.Certificate, *rsa.PrivateKey, string) {
				certs, privKey, didStr := defaultIn(t)
				certs[0] = &x509.Certificate{}
				return certs, privKey, didStr
			},
			errorText: "no values found in the SAN attributes, please check if the certificate is an UZI Server Certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certificates, signingKey, subject := tt.in(t)
			_, err := Issue(certificates, certificates[2], signingKey, subject)
			if tt.errorText == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tt.errorText)
			}
		})
	}
}

func TestIssue(t *testing.T) {
	validKey, err := internal.ParseRSAPrivateKeyFromPEM([]byte(internal.TestSigningKey))
	require.NoError(t, err, "failed to parse signing key")
	t.Run("ok - happy path", func(t *testing.T) {
		validChain, err := internal.ParseCertificatesFromPEM([]byte(internal.TestCertificateChain))
		require.NoError(t, err, "failed to parse chain")

		vc, err := Issue(validChain, validChain[3], validKey, "did:example:123", SubjectAttributes(x509_cert.SubjectTypeCountry, x509_cert.SubjectTypeOrganization, x509_cert.SubjectTypeLocality))

		require.NoError(t, err, "failed to issue verifiable credential")
		require.NotNil(t, vc, "verifiable credential is nil")

		assert.Equal(t, "https://www.w3.org/2018/credentials/v1", vc.Context[0].String())
		assert.True(t, vc.IsType(ssi.MustParseURI("VerifiableCredential")))
		assert.True(t, vc.IsType(ssi.MustParseURI("X509Credential")))
		assert.Equal(t, "did:x509:0:sha256:DwXSf2_jaUod7cezXBGJBM4AaaoA8DI9j7aPMDTI-mQ::san:otherName:2.16.528.1.1007.99.2110-1-1111111-S-2222222-00.000-333333::subject:L:Testland:O:Faux%20Care", vc.Issuer.String())

		expectedCredentialSubject := []interface{}{map[string]interface{}{
			"id": "did:example:123",
			"subject": map[string]interface{}{
				"O": "Faux Care",
				"L": "Testland",
			},
			"san": map[string]interface{}{
				"otherName":                    "2.16.528.1.1007.99.2110-1-1111111-S-2222222-00.000-333333",
				"permanentIdentifier.assigner": "2.16.528.1.1007.3.3",
				"permanentIdentifier.value":    "2222222",
			},
		}}

		assert.Equal(t, expectedCredentialSubject, vc.CredentialSubject)
		assert.Equal(t, validChain[0].NotAfter, *vc.ExpirationDate, "expiration date of VC must match signing certificate")
	})

	t.Run("ok - correct escaping of special characters", func(t *testing.T) {
		validChain, err := internal.ParseCertificatesFromPEM([]byte(internal.TestCertificateChain))
		require.NoError(t, err)

		validChain[0].Subject.Organization = []string{"FauxCare & Co"}

		vc, err := Issue(validChain, validChain[3], validKey, "did:example:123", SubjectAttributes(x509_cert.SubjectTypeCountry, x509_cert.SubjectTypeOrganization))

		assert.Equal(t, "did:x509:0:sha256:DwXSf2_jaUod7cezXBGJBM4AaaoA8DI9j7aPMDTI-mQ::san:otherName:2.16.528.1.1007.99.2110-1-1111111-S-2222222-00.000-333333::subject:O:FauxCare%20%26%20Co", vc.Issuer.String())
	})
}
