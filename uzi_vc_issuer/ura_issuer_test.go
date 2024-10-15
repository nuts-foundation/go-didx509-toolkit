package uzi_vc_issuer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestBuildUraVerifiableCredential(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().AddDate(0, 0, 1),
		IsCA:         true,
	}
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(derBytes)

	tests := []struct {
		name string
		in   func() ([]*x509.Certificate, *rsa.PrivateKey, string)
		want func(error) bool
	}{
		{
			name: "invalid signing certificate",
			in: func() ([]*x509.Certificate, *rsa.PrivateKey, string) {
				certs := []*x509.Certificate{cert}
				return certs, privKey, "did:example:123"
			},
			want: func(err error) bool {
				return err != nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certificates, signingKey, subjectDID := tt.in()
			_, err := BuildUraVerifiableCredential(certificates, signingKey, subjectDID)
			if got := tt.want(err); !got {
				t.Errorf("BuildUraVerifiableCredential() error = %v", err)
			}
		})
	}
}
