package azure

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_parseKeyURL(t *testing.T) {
	t.Run("missing /keys", func(t *testing.T) {
		_, _, _, err := parseKeyURL("https://someinstance.vault.azure.net/some/other/path")
		require.EqualError(t, err, "invalid Azure Key Vault key URL: https://someinstance.vault.azure.net/some/other/path")
	})
	t.Run("without version", func(t *testing.T) {
		vaultURL, keyName, keyVersion, err := parseKeyURL("https://someinstance.vault.azure.net/keys/name")
		require.NoError(t, err)
		require.Equal(t, "https://someinstance.vault.azure.net", vaultURL)
		require.Equal(t, "name", keyName)
		require.Equal(t, "", keyVersion)
	})
	t.Run("with version", func(t *testing.T) {
		vaultURL, keyName, keyVersion, err := parseKeyURL("https://someinstance.vault.azure.net/keys/name/version")
		require.NoError(t, err)
		require.Equal(t, "https://someinstance.vault.azure.net", vaultURL)
		require.Equal(t, "name", keyName)
		require.Equal(t, "version", keyVersion)
	})
}

func TestGetSigningKey(t *testing.T) {
	keyVaultServer := NewTestServer()
	AzureHttpRequestDoer = keyVaultServer.TestHttpServer.Client()
	privateKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	keyVaultServer.AddKey("sig", privateKey)

	signingKey, err := GetSigningKey(context.Background(), keyVaultServer.TestHttpServer.URL+"/keys/sig", "default")
	require.NoError(t, err)
	require.NotNil(t, signingKey)
}
