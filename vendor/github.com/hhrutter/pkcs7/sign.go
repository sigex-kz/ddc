package pkcs7

import (
	"crypto"
	"crypto/dsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// SignedData is an opaque data structure for creating signed data payloads
type SignedData struct {
	sd    signedData
	certs []*x509.Certificate
}

// NewSignedData initializes a PKCS7 SignedData struct that is ready to be signed via AddSigner.
func NewSignedData() (*SignedData, error) {
	sd := signedData{
		ContentInfo: contentInfo{ContentType: OIDData},
		Version:     1,
	}
	return &SignedData{sd: sd}, nil
}

// SignerInfoConfig are optional values to include when adding a signer
type SignerInfoConfig struct {
	ExtraSignedAttributes   []Attribute
	ExtraUnsignedAttributes []Attribute
}

type signedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                contentInfo
	Certificates               rawCertificates `asn1:"optional,tag:0"`
	CRLs                       []asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos                []SignerInfo    `asn1:"set"`
}

type SignerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"optional,omitempty,tag:0"` // RFC5652: signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte      `asn1:"octet"`
	UnauthenticatedAttributes []attribute `asn1:"optional,omitempty,tag:1"` // RFC5652: unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL
}

type ESSCertID struct {
	CertHash              []byte
	IssuerAndSerialNumber issuerAndSerial `asn1:"optional"`
}

type SigningCertificate struct {
	Certs []ESSCertID `asn1:"sequence"`
	// Policies omitted (optional, rarely present)
}

type ESSCertIDv2 struct {
	HashAlgorithm         pkix.AlgorithmIdentifier `asn1:"optional"` // DEFAULT sha256
	CertHash              []byte
	IssuerAndSerialNumber issuerAndSerial `asn1:"optional"`
}

type SigningCertificateV2 struct {
	Certs []ESSCertIDv2
}

type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

func marshalAttributes(attrs []attribute) ([]byte, error) {
	encodedAttributes, err := asn1.Marshal(struct {
		A []attribute `asn1:"set"`
	}{A: attrs})
	if err != nil {
		return nil, err
	}

	// Remove the leading sequence octets
	var raw asn1.RawValue
	asn1.Unmarshal(encodedAttributes, &raw)
	return raw.Bytes, nil
}

type rawCertificates struct {
	Raw asn1.RawContent
}

type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

func addDigestAlgorithmUnique(list []pkix.AlgorithmIdentifier, oid asn1.ObjectIdentifier) []pkix.AlgorithmIdentifier {
	for _, alg := range list {
		if alg.Algorithm.Equal(oid) {
			return list
		}
	}
	return append(list, pkix.AlgorithmIdentifier{Algorithm: oid})
}

// AddSigner is a wrapper around AddSignerChain() that adds a signer without any parent.
func (sd *SignedData) AddSigner(cert *x509.Certificate, pkey crypto.PrivateKey, messageDigest []byte, digestOid asn1.ObjectIdentifier, config SignerInfoConfig) error {
	var parents []*x509.Certificate
	return sd.AddSignerChain(cert, pkey, messageDigest, digestOid, parents, config)
}

func forcePositiveInteger(n *big.Int) *big.Int {
	b := n.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		// Prefix 0x00 to make it positive for DER INTEGER encoding
		b = append([]byte{0x00}, b...)
		return new(big.Int).SetBytes(b)
	}
	return n
}

// AddSignerChain signs attributes about the content and adds certificates
// and signers infos to the Signed Data. The certificate and private key
// of the end-entity signer are used to issue the signature, and any
// parent of that end-entity that need to be added to the list of
// certifications can be specified in the parents slice.
//
// The signature algorithm used to hash the data is the one of the end-entity certificate aka the cert.
func (sd *SignedData) AddSignerChain(cert *x509.Certificate, pkey crypto.PrivateKey, messageDigest []byte, digestOid asn1.ObjectIdentifier, parents []*x509.Certificate, config SignerInfoConfig) error {

	// Digest algorithm registration
	sd.sd.DigestAlgorithmIdentifiers = addDigestAlgorithmUnique(sd.sd.DigestAlgorithmIdentifiers, digestOid)

	// IssuerAndSerialNumber
	var ias issuerAndSerial
	ias.SerialNumber = forcePositiveInteger(cert.SerialNumber)
	if len(parents) == 0 {
		ias.IssuerName = asn1.RawValue{FullBytes: cert.RawIssuer}
	} else {
		ias.IssuerName = asn1.RawValue{FullBytes: parents[0].RawSubject}
	}

	// DigestEncryptionAlgorithm
	encryptionOid, err := OIDForEncryptionAlgorithm(pkey, digestOid)
	if err != nil {
		return err
	}

	// AuthenticatedAttributes
	attrs := &attributes{}
	attrs.Add(OIDAttributeContentType, sd.sd.ContentInfo.ContentType)
	attrs.Add(OIDAttributeMessageDigest, messageDigest)
	for _, attr := range config.ExtraSignedAttributes {
		attrs.Add(attr.Type, attr.Value)
	}
	authAttrs, err := attrs.ForMarshalling()
	if err != nil {
		return err
	}

	// UnauthenticatedAttributes
	attrs = &attributes{}
	for _, attr := range config.ExtraUnsignedAttributes {
		attrs.Add(attr.Type, attr.Value)
	}
	unauthAttrs, err := attrs.ForMarshalling()
	if err != nil {
		return err
	}

	// EncryptedDigest
	hash, err := HashForOID(digestOid)
	if err != nil {
		return err
	}
	signature, err := signAttributes(authAttrs, pkey, hash)
	if err != nil {
		return err
	}

	signerInfo := SignerInfo{
		Version:                   1, // RFC5652: If the SignerIdentifier is the CHOICE issuerAndSerialNumber, then the version MUST be 1
		IssuerAndSerialNumber:     ias,
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: digestOid},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: encryptionOid},
		EncryptedDigest:           signature,
		AuthenticatedAttributes:   authAttrs,
		UnauthenticatedAttributes: unauthAttrs,
	}

	sd.certs = append(sd.certs, cert)
	if len(parents) > 0 {
		sd.certs = append(sd.certs, parents...)
	}

	sd.sd.SignerInfos = append(sd.sd.SignerInfos, signerInfo)

	return nil
}

// AddCertificate adds the certificate to the payload. Useful for parent certificates
func (sd *SignedData) AddCertificate(cert *x509.Certificate) {
	sd.certs = append(sd.certs, cert)
}

// Detach removes content from the signed data struct to make it a detached signature.
// This must be called right before Finish()
func (sd *SignedData) Detach() {
	sd.sd.ContentInfo = contentInfo{ContentType: OIDData}
}

// GetSignedData returns the private Signed Data
func (sd *SignedData) GetSignedData() *signedData {
	return &sd.sd
}

// Even though, the tag & length are stripped out during marshalling the
// RawContent, we have to encode it into the RawContent. If its missing,
// then `asn1.Marshal()` will strip out the certificate wrapper instead.
func marshalCertificateBytes(certs []byte) (rawCertificates, error) {
	var val = asn1.RawValue{Bytes: certs, Class: 2, Tag: 0, IsCompound: true}
	b, err := asn1.Marshal(val)
	if err != nil {
		return rawCertificates{}, err
	}
	return rawCertificates{Raw: b}, nil
}

func marshalCertificates(certs []*x509.Certificate) (rawCertificates, error) {
	if len(certs) == 0 {
		return rawCertificates{}, nil
	}
	var certsBuf []byte
	for _, c := range certs {
		certsBuf = append(certsBuf, c.Raw...)
	}
	rawCerts, err := marshalCertificateBytes(certsBuf)
	if err != nil {
		return rawCertificates{}, err
	}
	return rawCerts, nil
}

func (sd *SignedData) Finish() ([]byte, error) {
	certsRaw, err := marshalCertificates(sd.certs)
	if err != nil {
		return nil, err
	}
	sd.sd.Certificates = certsRaw
	inner, err := asn1.Marshal(sd.sd)
	if err != nil {
		return nil, err
	}
	// Wrap in outer ContentInfo [0] EXPLICIT
	outer := contentInfo{
		ContentType: OIDSignedData,
		Content: asn1.RawValue{
			Class:      2,
			Tag:        0,
			Bytes:      inner,
			IsCompound: true,
		},
	}
	return asn1.Marshal(outer)
}

// verifyPartialChain checks that a given cert is issued by the first parent in the list,
// then continue down the path. It doesn't require the last parent to be a root CA,
// or to be trusted in any truststore. It simply verifies that the chain provided, albeit
// partial, makes sense.
func verifyPartialChain(cert *x509.Certificate, parents []*x509.Certificate) error {
	if len(parents) == 0 {
		return fmt.Errorf("pkcs7: zero parents provided to verify the signature of certificate %q", cert.Subject.CommonName)
	}
	err := cert.CheckSignatureFrom(parents[0])
	if err != nil {
		return fmt.Errorf("pkcs7: certificate signature from parent is invalid: %v", err)
	}
	if len(parents) == 1 {
		// there is no more parent to check, return
		return nil
	}
	return verifyPartialChain(parents[0], parents[1:])
}

func cert2issuerAndSerial(cert *x509.Certificate) (issuerAndSerial, error) {
	var ias issuerAndSerial
	// The issuer RDNSequence has to match exactly the sequence in the certificate
	// We cannot use cert.Issuer.ToRDNSequence() here since it mangles the sequence
	ias.IssuerName = asn1.RawValue{FullBytes: cert.RawIssuer}
	ias.SerialNumber = cert.SerialNumber
	return ias, nil
}

// signs the DER encoded form of the attributes with the private key
func signAttributes(attrs []attribute, pkey crypto.PrivateKey, digestAlg crypto.Hash) ([]byte, error) {
	attrBytes, err := marshalAttributes(attrs)
	if err != nil {
		return nil, err
	}
	h := digestAlg.New()
	h.Write(attrBytes)
	hash := h.Sum(nil)
	switch pkey.(type) {
	case *dsa.PrivateKey:
		return nil, errors.New("pkcs7: DSA not approved by NIST for signature creation")
	}
	key, ok := pkey.(crypto.Signer)
	if !ok {
		return nil, errors.New("pkcs7: private key does not implement crypto.Signer")
	}
	return key.Sign(rand.Reader, hash, digestAlg)
}

// DegenerateCertificate creates a signed data structure containing only the provided certificate or certificate chain.
func DegenerateCertificate(cert []byte) ([]byte, error) {
	rawCert, err := marshalCertificateBytes(cert)
	if err != nil {
		return nil, err
	}
	emptyContent := contentInfo{ContentType: OIDData}
	sd := signedData{
		Version:      1,
		ContentInfo:  emptyContent,
		Certificates: rawCert,
		CRLs:         nil,
	}
	content, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	signedContent := contentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: content, IsCompound: true},
	}
	return asn1.Marshal(signedContent)
}
