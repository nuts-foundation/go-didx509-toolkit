package credential_issuer

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jws"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-didx509-toolkit/internal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssueHealthcareProviderCredential(t *testing.T) {
	chain, err := internal.ParseCertificatesFromPEM([]byte(internal.TestCertificateChain))
	require.NoError(t, err)
	key, err := internal.ParseRSAPrivateKeyFromPEM([]byte(internal.TestSigningKey))
	require.NoError(t, err)

	credential, err := IssueHealthcareProviderCredential(chain, chain[3], key,
		"did:web:ziekenhuis-voorbeeld.nl")
	require.NoError(t, err)
	require.NotNil(t, credential)

	assert.True(t, credential.IsType(ssi.MustParseURI("VerifiableCredential")))
	assert.True(t, credential.IsType(HealthcareProviderCredentialType))
	require.Len(t, credential.Context, 2)
	assert.Equal(t, "https://www.w3.org/2018/credentials/v1", credential.Context[0].String())
	assert.Equal(t, "https://vzvz.nl/credentials/v1", credential.Context[1].String())

	// Shape per the AORTA-on-FHIR HealthcareProviderCredential spec: @type HealthcareProvider,
	// a single identifier object (@type Identifier, URA system+value) and the organization name.
	expectedSubject := []map[string]any{{
		"id":    "did:web:ziekenhuis-voorbeeld.nl",
		"@type": "HealthcareProvider",
		"identifier": map[string]any{
			"@type":  "Identifier",
			"system": "http://fhir.nl/fhir/NamingSystem/ura",
			"value":  "2222222",
		},
		"name": "Faux Care",
	}}
	assert.Equal(t, expectedSubject, credential.CredentialSubject)
	assert.Equal(t, chain[0].NotAfter, *credential.ExpirationDate)

	t.Run("credentialSubject is serialized as a JSON object, not an array", func(t *testing.T) {
		parsed, err := jws.Parse([]byte(credential.Raw()))
		require.NoError(t, err)
		var payload struct {
			VC struct {
				CredentialSubject json.RawMessage `json:"credentialSubject"`
			} `json:"vc"`
		}
		require.NoError(t, json.Unmarshal(parsed.Payload(), &payload))
		require.NotEmpty(t, payload.VC.CredentialSubject)
		assert.Equal(t, byte('{'), payload.VC.CredentialSubject[0], "credentialSubject must be a JSON object, got: %s", string(payload.VC.CredentialSubject))
	})
}
