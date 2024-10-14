package uzi_vc_validator

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/vc"
	"headease-nuts-pki-overheid-issuer/ca_certs"
	"headease-nuts-pki-overheid-issuer/did_x509"
	pem2 "headease-nuts-pki-overheid-issuer/pem"
	"headease-nuts-pki-overheid-issuer/x509_cert"
)

type UraValidator interface {
	Validate(jwtString []byte) bool
}

type UraValidatorImpl struct {
	test bool
}

type JwtHeaderValues struct {
	X509CertThumbprint     string
	X509CertChain          *cert.Chain
	X509CertThumbprintS256 string
	Algorithm              jwa.SignatureAlgorithm
}

func (u UraValidatorImpl) Validate(jwtString string) error {
	credential := &vc.VerifiableCredential{}
	err := json.Unmarshal([]byte("\""+jwtString+"\""), credential)
	if err != nil {
		return err
	}
	parseDid, err := did_x509.ParseDid(credential.Issuer.String())
	if err != nil {
		return err
	}
	headerValues, err := parseJwtHeaderValues(jwtString)
	if err != nil {
		return err
	}

	chainCertificates, err := parseCertificate(headerValues.X509CertChain)
	if err != nil {
		return err
	}

	signingCert, err := findSigningCertificate(chainCertificates, headerValues.X509CertThumbprint)
	if err != nil {
		return err
	}

	err = validateChain(signingCert, chainCertificates, u.test)
	if err != nil {
		return err
	}

	var options []jwt.ParseOption
	options = append(options, jwt.WithKey(headerValues.Algorithm, signingCert.PublicKey))
	options = append(options, jwt.WithVerify(true))

	_, err = jwt.ParseString(jwtString, options...)
	if err != nil {
		return err
	}
	ura, sanType, err := x509_cert.FindOtherName(signingCert)
	if err != nil {
		return err
	}

	if ura != parseDid.Ura {
		return fmt.Errorf("Ura in credential does not match Ura in signing certificate")
	}
	if sanType != parseDid.SanType {
		return fmt.Errorf("SanType in credential does not match SanType in signing certificate")
	}

	return nil
}

func validateChain(signingCert *x509.Certificate, certificates *[]x509.Certificate, includeTest bool) error {
	var err error
	intermediates := x509.NewCertPool()
	roots := x509.NewCertPool()
	for _, c := range *certificates {
		if x509_cert.IsIntermediateCa(&c) {
			intermediates.AddCert(&c)
		} else if x509_cert.IsRootCa(&c) {
			roots.AddCert(&c)
		}
	}

	// First validate against the own provided pool
	err = validate(signingCert, roots, intermediates)
	if err != nil {
		err = fmt.Errorf("could not validate against own provided pool: %s", err.Error())
		return err
	}
	root, intermediate, err := ca_certs.GetCertPools(includeTest)
	if err != nil {
		return err
	}
	err = validate(signingCert, root, intermediate)
	if err != nil {
		err = fmt.Errorf("could not validate against the CA pool from zorgcsp (includeTest=%v): %s", includeTest, err.Error())
		return err
	}
	return nil
}

func validate(signingCert *x509.Certificate, roots *x509.CertPool, intermediates *x509.CertPool) error {
	opts := x509.VerifyOptions{
		Roots:         roots,
		DNSName:       "",
		Intermediates: intermediates,
	}
	if _, err := signingCert.Verify(opts); err != nil {
		return err
	}
	return nil
}

func findSigningCertificate(certificates *[]x509.Certificate, thumbprint string) (*x509.Certificate, error) {
	for _, c := range *certificates {
		hashSha1 := sha1.Sum(c.Raw)
		if base64.RawURLEncoding.EncodeToString(hashSha1[:]) == thumbprint {
			return &c, nil
		}
	}
	return nil, fmt.Errorf("Could not find certificate with thumbprint %s", thumbprint)
}

func parseCertificate(chain *cert.Chain) (*[]x509.Certificate, error) {
	var certificates []x509.Certificate
	for i := 0; i < chain.Len(); i++ {
		bytes, _ := chain.Get(i)
		blocks := pem2.ParsePemBlocks(bytes, "CERTIFICATE")
		for _, block := range *blocks {
			found, err := x509.ParseCertificates(block)
			if err != nil {
				return nil, err
			}
			for _, c := range found {
				if c != nil {
					certificates = append(certificates, *c)
				}
			}
		}
	}
	return &certificates, nil
}

func parseJwtHeaderValues(jwtString string) (*JwtHeaderValues, error) {
	message, err := jws.ParseString(jwtString)
	if err != nil {
		return nil, err
	}
	metadata := &JwtHeaderValues{}
	if message != nil && len(message.Signatures()) > 0 {
		headers := message.Signatures()[0].ProtectedHeaders()
		metadata.X509CertThumbprint = headers.X509CertThumbprint()
		metadata.X509CertChain = headers.X509CertChain()
		metadata.X509CertThumbprintS256 = headers.X509CertThumbprintS256()
		metadata.Algorithm = headers.Algorithm()
	}
	return metadata, nil
}

func NewUraValidator(test bool) *UraValidatorImpl {
	return &UraValidatorImpl{test}
}
