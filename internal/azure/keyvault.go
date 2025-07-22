package azure

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"io"
	"net/http"
	"os"
	"strings"
)

var AzureHttpRequestDoer HttpRequestDoer = http.DefaultClient

type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

func GetSigningKey(ctx context.Context, keyURL string, authType string) (crypto.Signer, error) {
	credential, err := createCredential(authType)
	if err != nil {
		return nil, err
	}
	vaultURL, keyName, keyVersion, err := parseKeyURL(keyURL)
	if err != nil {
		return nil, err
	}
	client, err := azkeys.NewClient(vaultURL, credential, &azkeys.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: AzureHttpRequestDoer,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create Azure Key Vault client: %w", err)
	}
	return getPrivateKey(ctx, client, keyName, keyVersion)
}

func parseKeyURL(keyURL string) (string, string, string, error) {
	// URL should be in the form of:
	//   https://someinstance.vault.azure.net/keys/name(/version, optional)
	idx := strings.Index(keyURL, "/keys/")
	if idx < 0 {
		return "", "", "", fmt.Errorf("invalid Azure Key Vault key URL: %s", keyURL)
	}
	vaultURL := keyURL[:idx]
	keyNameAndVersion := keyURL[idx+6:] // +6 to skip "/keys/"
	idx = strings.Index(keyNameAndVersion, "/")
	var keyName string
	var keyVersion string
	if idx < 0 {
		keyName = keyNameAndVersion
	} else {
		keyName = keyNameAndVersion[:idx]
		keyVersion = keyNameAndVersion[idx+1:] // +1 to skip the "/"
	}
	return vaultURL, keyName, keyVersion, nil
}

func createCredential(credentialType string) (azcore.TokenCredential, error) {
	switch credentialType {
	case "default":
		return azidentity.NewDefaultAzureCredential(nil)
	case "managed_identity":
		opts := &azidentity.ManagedIdentityCredentialOptions{
			ClientOptions: azcore.ClientOptions{},
		}
		// For UserAssignedManagedIdentity, client ID needs to be explicitly set.
		// Taken from github.com/!azure/azure-sdk-for-go/sdk/azidentity@v1.7.0/default_azure_credential.go:100
		if ID, ok := os.LookupEnv("AZURE_CLIENT_ID"); ok {
			opts.ID = azidentity.ClientID(ID)
		}
		return azidentity.NewManagedIdentityCredential(opts)
	default:
		return nil, fmt.Errorf("unsupported Azure Key Vault credential type: %s", credentialType)
	}
}

func getPrivateKey(ctx context.Context, client *azkeys.Client, keyName string, version string) (crypto.Signer, error) {
	response, err := client.GetKey(ctx, keyName, version, nil)
	if err != nil {
		// other error
		return nil, fmt.Errorf("unable to get key from Azure Key Vault (name=%s): %w", keyName, err)
	}
	publicKey, signingAlgorithm, parsedKeyVersion, err := parseKey(response.Key)
	if err != nil {
		return nil, err
	}
	return &azureSigningKey{
		ctx:              ctx,
		client:           client,
		keyName:          keyName,
		keyVersion:       parsedKeyVersion,
		publicKey:        publicKey,
		signingAlgorithm: signingAlgorithm,
	}, nil
}

// parseKey parses an Azure Key Vault key into a crypto.PublicKey and selects the azkeys.SignatureAlgorithm.
func parseKey(key *azkeys.JSONWebKey) (publicKey crypto.PublicKey, keyType azkeys.SignatureAlgorithm, version string, err error) {
	jwkData, _ := json.Marshal(key)
	keyAsJWK, err := jwk.ParseKey(jwkData)
	if err != nil {
		err = fmt.Errorf("unable to parse key from Azure Key Vault as JWK: %w", err)
		return
	}
	if err = keyAsJWK.Raw(&publicKey); err != nil {
		err = fmt.Errorf("unable to convert key from Azure Key Vault Key to crypto.PublicKey: %w", err)
		return
	}
	if !(*key.Kty == azkeys.KeyTypeRSA) {
		err = errors.New("only RSA keys are supported")
		return
	}
	keyType = azkeys.SignatureAlgorithmPS256
	if key.KID == nil {
		err = errors.New("missing KID in key")
		return
	}
	version = key.KID.Version()
	return
}

var _ crypto.Signer = &azureSigningKey{}

type azureSigningKey struct {
	ctx              context.Context
	client           keyVaultClient
	keyName          string
	keyVersion       string
	publicKey        crypto.PublicKey
	signingAlgorithm azkeys.SignatureAlgorithm
}

// keyVaultClient is an interface for the Azure Key Vault client, to support mocking.
type keyVaultClient interface {
	Sign(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
}

func (a azureSigningKey) Public() crypto.PublicKey {
	return a.publicKey
}

func (a azureSigningKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	// Sanity check
	if opts != nil && opts.HashFunc() == 0 {
		return nil, errors.New("hashing should've been done")
	}
	var signingAlgorithm azkeys.SignatureAlgorithm
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		switch pssOpts.Hash.Size() {
		case sha256.Size:
			signingAlgorithm = azkeys.SignatureAlgorithmPS256
		default:
			return nil, fmt.Errorf("unsupported PSS hash size: %d", pssOpts.Hash.Size())
		}
	} else {
		switch opts.HashFunc().Size() {
		case sha256.Size:
			signingAlgorithm = azkeys.SignatureAlgorithmRS256
		default:
			return nil, errors.New("unsupported RSA hash size")
		}
	}
	response, err := a.client.Sign(a.ctx, a.keyName, a.keyVersion, azkeys.SignParameters{
		Algorithm: to.Ptr(signingAlgorithm),
		Value:     digest,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to sign with Azure KeyVault: %w", err)
	}
	return response.Result, nil
}
