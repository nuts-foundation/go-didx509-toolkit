package x509_cert

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-didx509-toolkit/internal"
	"slices"
)

type otherName struct {
	TypeID asn1.ObjectIdentifier
	Value  asn1.RawValue `asn1:"tag:0,explicit"`
}

type stringAndOid struct {
	Value    string
	Assigner asn1.ObjectIdentifier
}

type PolicyType = string

const (
	PolicyTypeSan     PolicyType = "san"
	PolicyTypeSubject PolicyType = "subject"
)

type SanTypeName = string

const (
	SanTypeOtherName                   SanTypeName = "otherName"
	SanTypePermanentIdentifierValue    SanTypeName = "permanentIdentifier.value"
	SanTypePermanentIdentifierAssigner SanTypeName = "permanentIdentifier.assigner"
)

type SubjectTypeName = string

const (
	SubjectTypeCommonName         SubjectTypeName = "CN"
	SubjectTypeOrganization       SubjectTypeName = "O"
	SubjectTypeOrganizationalUnit SubjectTypeName = "OU"
	SubjectTypeCountry            SubjectTypeName = "C"
	SubjectTypeLocality           SubjectTypeName = "L"
	SubjectTypeProvince           SubjectTypeName = "ST"
	SubjectTypeStreetAddress      SubjectTypeName = "STREET"
	SubjectTypeSerialNumber       SubjectTypeName = "serialNumber"
)

type PolicyValue struct {
	PolicyType PolicyType
	Type       string
	Value      string
}

func FindSubjectTypes(certificate *x509.Certificate) ([]*PolicyValue, error) {
	rv := make([]*PolicyValue, 0)
	if certificate == nil {
		return nil, errors.New("certificate is nil")
	}
	rv = append(rv, getStringListSubjectValues(SubjectTypeCommonName, certificate.Subject.CommonName)...)
	rv = append(rv, getStringListSubjectValues(SubjectTypeOrganization, certificate.Subject.Organization...)...)
	rv = append(rv, getStringListSubjectValues(SubjectTypeOrganizationalUnit, certificate.Subject.OrganizationalUnit...)...)
	rv = append(rv, getStringListSubjectValues(SubjectTypeCountry, certificate.Subject.Country...)...)
	rv = append(rv, getStringListSubjectValues(SubjectTypeLocality, certificate.Subject.Locality...)...)
	rv = append(rv, getStringListSubjectValues(SubjectTypeProvince, certificate.Subject.Province...)...)
	rv = append(rv, getStringListSubjectValues(SubjectTypeStreetAddress, certificate.Subject.StreetAddress...)...)
	rv = append(rv, getStringListSubjectValues(SubjectTypeSerialNumber, certificate.Subject.SerialNumber)...)
	return rv, nil
}

func SelectSubjectTypes(certificate *x509.Certificate, subjectAttributes ...SubjectTypeName) ([]*PolicyValue, error) {
	subjectTypes, err := FindSubjectTypes(certificate)
	if err != nil {
		return nil, err
	}
	var selectedSubjectTypes []*PolicyValue
	for _, subjectType := range subjectTypes {
		if slices.Contains(subjectAttributes, subjectType.Type) {
			selectedSubjectTypes = append(selectedSubjectTypes, subjectType)
		}
	}
	return selectedSubjectTypes, nil
}

func getStringListSubjectValues(subjectType SubjectTypeName, values ...string) []*PolicyValue {
	rv := make([]*PolicyValue, 0)
	if len(values) > 0 {
		for _, c := range values {
			rv = append(rv, &PolicyValue{
				PolicyType: PolicyTypeSubject,
				Type:       subjectType,
				Value:      c,
			})
		}
	}
	return rv
}

func FindSanTypes(certificate *x509.Certificate) ([]*PolicyValue, error) {
	rv := make([]*PolicyValue, 0)
	if certificate == nil {
		return nil, errors.New("certificate is nil")
	}
	otherNameValue, err := findOtherNameValue(certificate)
	if err != nil {
		return nil, err
	}
	if otherNameValue != "" {
		rv = append(rv, &PolicyValue{
			Value:      otherNameValue,
			Type:       SanTypeOtherName,
			PolicyType: PolicyTypeSan,
		})
	}

	value, assigner, err := findPermanentIdentifiers(certificate)
	if err != nil {
		return nil, err
	}
	if value != "" {
		rv = append(rv, &PolicyValue{
			Value:      value,
			Type:       SanTypePermanentIdentifierValue,
			PolicyType: PolicyTypeSan,
		})
	}
	if len(assigner) > 0 {
		rv = append(rv, &PolicyValue{
			Value:      assigner.String(),
			Type:       SanTypePermanentIdentifierAssigner,
			PolicyType: PolicyTypeSan,
		})
	}
	if len(rv) == 0 {
		err = errors.New("no values found in the SAN attributes, please check if the certificate is an UZI Server Certificate")
		return nil, err
	}
	return rv, nil
}

func SelectSanTypes(certificate *x509.Certificate, sanTypes ...SanTypeName) ([]*PolicyValue, error) {
	subjectTypes, err := FindSanTypes(certificate)
	if err != nil {
		return nil, err
	}
	var selectedSubjectTypes []*PolicyValue
	for _, subjectType := range subjectTypes {
		if slices.Contains(sanTypes, subjectType.Type) {
			selectedSubjectTypes = append(selectedSubjectTypes, subjectType)
		}
	}
	return selectedSubjectTypes, nil
}

func findPermanentIdentifiers(cert *x509.Certificate) (string, asn1.ObjectIdentifier, error) {
	value := ""
	var assigner asn1.ObjectIdentifier
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(internal.SubjectAlternativeNameType) {
			err := forEachSAN(extension.Value, func(tag int, data []byte) error {
				if tag != 0 {
					return nil
				}
				var other otherName
				_, err := asn1.UnmarshalWithParams(data, &other, "tag:0")
				if err != nil {
					return fmt.Errorf("could not parse requested other SAN: %v", err)
				}
				if other.TypeID.Equal(internal.PermanentIdentifierType) {
					var x stringAndOid
					_, err = asn1.Unmarshal(other.Value.Bytes, &x)
					if err != nil {
						return err
					}
					value = x.Value
					assigner = x.Assigner

				}
				return nil
			})
			if err != nil {
				return "", nil, err
			}

			return value, assigner, err
		}
	}
	return "", nil, nil
}

func findOtherNameValue(cert *x509.Certificate) (string, error) {
	value := ""
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(internal.SubjectAlternativeNameType) {
			err := forEachSAN(extension.Value, func(tag int, data []byte) error {
				if tag != 0 {
					return nil
				}
				var other otherName
				_, err := asn1.UnmarshalWithParams(data, &other, "tag:0")
				if err != nil {
					return fmt.Errorf("could not parse requested other SAN: %v", err)
				}
				if other.TypeID.Equal(internal.OtherNameType) {
					_, err = asn1.Unmarshal(other.Value.Bytes, &value)
					if err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return "", err
			}
			return value, err
		}
	}
	return "", nil
}

// forEachSAN iterates over each SAN (Subject Alternative Name) in the provided ASN.1 encoded extension.
// It unmarshals the extension and checks if it is a valid SAN sequence, then processes each element using the callback.
func forEachSAN(extension []byte, callback func(tag int, data []byte) error) error {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("x509: trailing data after X.509 extension")
	}

	if !isSANSequence(seq) {
		return asn1.StructuralError{Msg: "bad SAN sequence"}
	}

	return processSANSequence(seq.Bytes, callback)
}

// isSANSequence checks if the given ASN.1 raw value represents a valid SAN (Subject Alternative Name) sequence.
func isSANSequence(seq asn1.RawValue) bool {
	return seq.IsCompound && seq.Tag == 16 && seq.Class == 0
}

// processSANSequence processes a sequence of SAN (Subject Alternative Name) elements in ASN.1 encoding.
// It takes the remaining part of the sequence and a callback function to handle each SAN element.
// Each SAN element is passed to the callback function with its tag and full data bytes.
func processSANSequence(rest []byte, callback func(tag int, data []byte) error) error {
	for len(rest) > 0 {
		var v asn1.RawValue
		var err error

		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return err
		}

		if err := callback(v.Tag, v.FullBytes); err != nil {
			return err
		}
	}
	return nil
}
