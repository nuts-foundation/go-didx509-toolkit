package x509_cert

import (
	"crypto/x509"
	"encoding/asn1"
	"github.com/nuts-foundation/go-didx509-toolkit/internal"
	"github.com/stretchr/testify/require"
	"testing"
)

var permanentIdentifierAssigner = asn1.ObjectIdentifier{2, 16, 528, 1, 1007, 3, 3}

func TestFindOtherName(t *testing.T) {
	chain, _, _, _, _, err := internal.BuildSelfSignedCertChain("2.16.528.1.1007.99.2110-1-900030787-S-90000380-00.000-11223344", "90000380")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		certificate *x509.Certificate
		want        []*PolicyValue
		wantErr     bool
	}{
		{
			name:        "ValidOtherName",
			certificate: chain[0],
			want: []*PolicyValue{
				{
					PolicyType: PolicyTypeSan,
					Type:       SanTypeOtherName,
					Value:      "2.16.528.1.1007.99.2110-1-900030787-S-90000380-00.000-11223344",
				},
				{
					PolicyType: PolicyTypeSan,
					Type:       SanTypePermanentIdentifierValue,
					Value:      "90000380",
				},
				{
					PolicyType: PolicyTypeSan,
					Type:       SanTypePermanentIdentifierAssigner,
					Value:      permanentIdentifierAssigner.String(),
				},
			},
			wantErr: false,
		},
		{
			name:        "NoOtherName",
			certificate: chain[1], // This should be a valid initialised certificate without any otherName
			wantErr:     true,
		},
		{
			name:    "NilCertificate",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			otherNames, err := FindSanTypes(tt.certificate)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				if otherNames != nil {
					require.Equal(t, tt.want, otherNames)
				}
			}
		})
	}
}
