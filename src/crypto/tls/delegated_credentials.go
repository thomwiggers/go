// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// Delegated credentials for TLS
// (https://tools.ietf.org/html/draft-ietf-tls-subcerts) is an IETF Internet
// draft and proposed TLS extension. If the client supports this extension, then
// the server may use a "delegated credential" as the signing key in the
// handshake. A delegated credential is a short lived public/secret key pair
// delegated to the server by an entity trusted by the client. This allows a
// middlebox to terminate a TLS connection on behalf of the entity; for example,
// this can be used to delegate TLS termination to a reverse proxy. Credentials
// can't be revoked; in order to mitigate risk in case the middlebox is
// compromised, the credential is only valid for a short time (days, hours, or
// even minutes).

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	dcMaxTTLSeconds   = 60 * 60 * 24 * 7 // The maxium validity period is 7 days
	dcMaxTTL          = time.Duration(dcMaxTTLSeconds * time.Second)
	dcMaxPublicKeyLen = 1 << 16 // Bytes
	dcMaxSignatureLen = 1 << 16 // Bytes
)

// TODO: need to check if this is consistent with Golang's error handling
var errNoDelegationUsage = errors.New("certificate not authorized for delegation")

// delegationUsageID is the DelegationUsage X.509 extension OID
// TODO: how is this assigned?
var delegationUsageID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 44}

// CreateDelegationUsagePKIXExtension returns a pkix.Extension that every delegation
// certificate must have.
// TODO: we might not need this if we go for modifying x509
func CreateDelegationUsagePKIXExtension() *pkix.Extension {
	return &pkix.Extension{
		Id:       delegationUsageID,
		Critical: false,
		Value:    nil,
	}
}

// isValidForDelegation returns true if a certificate can be used for delegated
// credentials.
func isValidForDelegation(cert *x509.Certificate) bool {
	// Check that the digitalSignature key usage is set.
	// The certificate must contains the digitalSignature KeyUsage, as per
	// spec.
	if (cert.KeyUsage & x509.KeyUsageDigitalSignature) == 0 {
		return false
	}

	// Check that the certificate has the DelegationUsage extension and that
	// it's non-critical (See Section 4.2 of RFC5280).
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(delegationUsageID) {
			return true
		}
	}
	return false
}

// IsExpired returns true if the credential has expired. The end of the validity
// interval is defined as the delegator certificate's notBefore field ('start')
// plus ValidTime seconds. This function simply checks that the current time
// (`now`) is before the end of the valdity interval.
// TODO: the subsequent funcs can be unified
func (dc *DelegatedCredential) IsExpired(start, now time.Time) bool {
	end := start.Add(dc.ValidTime)
	return !now.Before(end)
}

// InvalidTTL returns true if the credential's validity period is longer than the
// maximum permitted. This is defined by the certificate's notBefore field
// (`start`) plus the ValidTime, minus the current time (`now`).
func (dc *DelegatedCredential) InvalidTTL(start, now time.Time) bool {
	return dc.ValidTime > (now.Sub(start) + dcMaxTTL).Round(time.Second)
}

// credential stores the public components.
type credential struct {
	validTime time.Duration
	publicKey crypto.PublicKey
	scheme    SignatureScheme
}

// DelegatedCredential stores the credential and its signature.
// TODO: this should use the credential struct.
type DelegatedCredential struct {
	// The serialized form of the credential.
	Raw []byte

	// The amount of time for which the credential is valid. Specifically, the
	// the credential expires `ValidTime` seconds after the `notBefore` of the
	// delegation certificate. The delegator shall not issue delegated
	// credentials that are valid for more than 7 days from the current time.
	//
	// When this data structure is serialized, this value is converted to a
	// uint32 representing the duration in seconds.
	ValidTime time.Duration

	// The credential public key.
	PublicKey crypto.PublicKey

	// The signature scheme associated with the credential public key.
	publicKeyScheme SignatureScheme

	// The signature scheme used to sign the credential.
	Scheme SignatureScheme

	// The credential's delegation.
	Signature []byte
}

// marshalSubjectPublicKeyInfo returns a DER encoded SubjectPublicKeyInfo structure
// (as defined in the X.509 standard) for the credential.
// TODO: maybe we can move this as well to x509
// TODO: add the other signatures flavors, as defined in common.go
func (cred *credential) marshalPublicKeyInfo() ([]byte, error) {
	switch cred.scheme {
	case ECDSAWithP256AndSHA256,
		ECDSAWithP384AndSHA384,
		ECDSAWithP521AndSHA512:
		serializedPublicKey, err := x509.MarshalPKIXPublicKey(cred.publicKey)
		if err != nil {
			return nil, err
		}
		return serializedPublicKey, nil

	default:
		return nil, fmt.Errorf("unsupported signature scheme: 0x%04x", cred.scheme)
	}
}

// unmarshalPublicKeyInfo parses a DER encoded PublicKeyInfo
// structure into a public key and its corresponding algorithm.
// TODO: add the other signatures flavors, as defined in common.go
func unmarshalPublicKeyInfo(serialized []byte) (crypto.PublicKey, SignatureScheme, error) {
	publicKey, err := x509.ParsePKIXPublicKey(serialized)
	if err != nil {
		return nil, 0, err
	}

	switch pk := publicKey.(type) {
	case *ecdsa.PublicKey:
		curveName := pk.Curve.Params().Name
		if curveName == "P-256" {
			return pk, ECDSAWithP256AndSHA256, nil
		} else if curveName == "P-384" {
			return pk, ECDSAWithP384AndSHA384, nil
		} else if curveName == "P-521" {
			return pk, ECDSAWithP521AndSHA512, nil
		} else {
			return nil, 0, fmt.Errorf("curve %s s not supported", curveName)
		}

	default:
		return nil, 0, fmt.Errorf("unsupported delgation key type: %T", pk)
	}
}

// marshal encodes the credential.
// TODO: might be better if this is a function and not a method
func (cred *credential) marshal() ([]byte, error) {
	// Write the valid_time field.
	serialized := make([]byte, 6)
	binary.BigEndian.PutUint32(serialized, uint32(cred.validTime/time.Second))

	// Encode the public key and assert that the encoding is no longer than 2^16
	// bytes (per the spec).
	// TODO: double check this
	serializedPublicKey, err := cred.marshalPublicKeyInfo()
	if err != nil {
		return nil, err
	}
	if len(serializedPublicKey) > dcMaxPublicKeyLen {
		// TODO: change this error
		return nil, errors.New("public key is too long")
	}

	// Write the length of the public_key field.
	binary.BigEndian.PutUint16(serialized[4:], uint16(len(serializedPublicKey)))

	// Write the public key.
	return append(serialized, serializedPublicKey...), nil
}

// unmarshalCredential decodes serialized bytes and returns a credential if possible.
func unmarshalCredential(serialized []byte) (*credential, error) {
	// Bytes 0-3 are the validity time field; bytes 4-6 are the length of the
	// serialized PublicKeyInfo.
	if len(serialized) < 6 {
		// TODO: change this error
		return nil, errors.New("credential is too short")
	}

	// Parse the validity time.
	validTime := time.Duration(binary.BigEndian.Uint32(serialized)) * time.Second

	// Parse the PublicKeyInfo.
	pk, scheme, err := unmarshalPublicKeyInfo(serialized[6:])
	if err != nil {
		return nil, err
	}

	return &credential{validTime, pk, scheme}, nil
}

// getCredentialLen returns the number of bytes comprising the serialized
// credential that starts at the beginning of the input slice. It returns an
// error if the input is too short to contain a credential.
func getCredentialLen(serialized []byte) (int, error) {
	if len(serialized) < 6 {
		// TODO: change this error
		return 0, errors.New("credential is too short")
	}
	// First 4 bytes is the validity time.
	serialized = serialized[4:]

	// The next 2 bytes are the length of the serialized public key.
	serializedPublicKeyLen := int(binary.BigEndian.Uint16(serialized))
	serialized = serialized[2:]

	if len(serialized) < serializedPublicKeyLen {
		return 0, errors.New("public key of credential is too short")
	}

	return 6 + serializedPublicKeyLen, nil
}

// getHash maps the SignatureScheme to its corresponding hash function.
// TODO: find the way golang handles this now
func getHash(scheme SignatureScheme) crypto.Hash {
	switch scheme {
	case ECDSAWithP256AndSHA256:
		return crypto.SHA256
	case ECDSAWithP384AndSHA384:
		return crypto.SHA384
	case ECDSAWithP521AndSHA512:
		return crypto.SHA512
	default:
		return 0 // Unknown hash function
	}
}

// getCurve maps the SignatureScheme to its corresponding elliptic.Curve.
// TODO: find the way golang handles this now
func getCurve(scheme SignatureScheme) elliptic.Curve {
	switch scheme {
	case ECDSAWithP256AndSHA256:
		return elliptic.P256()
	case ECDSAWithP384AndSHA384:
		return elliptic.P384()
	case ECDSAWithP521AndSHA512:
		return elliptic.P521()
	default:
		return nil
	}
}

// prepareDelegation returns a hash of the message that the delegator is to
// sign. The inputs are the credential ('cred'), the DER-encoded delegator
// certificate ('delegatorCert'), the signature scheme of the delegator
// ('delegatorScheme'), and the protocol version ('vers') in which the credential
// is to be used.
// TODO: needs to add 'TLS, client delegated credentials'
// TODO: does this need the hash?
func prepareDelegation(hash crypto.Hash, cred *credential, delegatorCert []byte, delegatorScheme SignatureScheme, vers uint16) ([]byte, error) {
	h := hash.New()

	h.Write(bytes.Repeat([]byte{0x20}, 64))
	h.Write([]byte("TLS, server delegated credentials"))
	h.Write([]byte{0x00})

	// TODO: not needed anymore.. was this removed from the draft?
	// The protocol version.
	//var serializedVers [2]byte
	//binary.BigEndian.PutUint16(serializedVers[:], uint16(vers))
	//h.Write(serializedVers[:])

	// The delegation certificate
	h.Write(delegatorCert)

	// The delegator signature scheme
	//var serializedScheme [2]byte
	//binary.BigEndian.PutUint16(serializedScheme[:], uint16(delegatorScheme))
	//h.Write(serializedScheme[:])

	// The credential.
	serializedCred, err := cred.marshal()
	if err != nil {
		return nil, err
	}
	h.Write(serializedCred)

	return h.Sum(nil), nil
}

// NewDelegatedCredential creates a new delegated credential using 'cert' for
// delegation. It generates a public/private key pair for the provided signature
// algorithm ('scheme'), validity interval (defined by 'cert.Leaf.notBefore' and
// 'validTime'), and TLS version ('vers'), and signs it using 'cert.PrivateKey'.
// TODO: add the other signature schemes
func NewDelegatedCredential(cert *Certificate, scheme SignatureScheme, validTime time.Duration, vers uint16) (*DelegatedCredential, crypto.PrivateKey, error) {
	// The granularity of DC validity is seconds.
	validTime = validTime.Round(time.Second)

	// Parse the leaf certificate if needed.
	var err error
	if cert.Leaf == nil {
		if len(cert.Certificate[0]) == 0 {
			return nil, nil, errors.New("missing leaf certificate")
		}
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, nil, err
		}
	}

	// Check that the leaf certificate can be used for delegation.
	if !isValidForDelegation(cert.Leaf) {
		return nil, nil, errNoDelegationUsage
	}

	// Extract the delegator signature scheme from the certificate.
	var delegatorScheme SignatureScheme
	switch sk := cert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		pk := sk.Public().(*ecdsa.PublicKey)
		curveName := pk.Curve.Params().Name
		certAlg := cert.Leaf.SignatureAlgorithm
		if certAlg == x509.ECDSAWithSHA256 && curveName == "P-256" {
			delegatorScheme = ECDSAWithP256AndSHA256
		} else if certAlg == x509.ECDSAWithSHA384 && curveName == "P-384" {
			delegatorScheme = ECDSAWithP384AndSHA384
		} else if certAlg == x509.ECDSAWithSHA512 && curveName == "P-521" {
			delegatorScheme = ECDSAWithP521AndSHA512
		} else {
			return nil, nil, fmt.Errorf(
				"using curve %s for %s is not supported",
				curveName, cert.Leaf.SignatureAlgorithm)
		}

	default:
		return nil, nil, fmt.Errorf("unsupported delgation key type: %T", sk)
	}

	// Generate a new key pair.
	var sk crypto.PrivateKey
	var pk crypto.PublicKey
	switch scheme {
	case ECDSAWithP256AndSHA256,
		ECDSAWithP384AndSHA384,
		ECDSAWithP521AndSHA512:
		sk, err = ecdsa.GenerateKey(getCurve(scheme), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pk = sk.(*ecdsa.PrivateKey).Public()

	default:
		return nil, nil, fmt.Errorf("unsupported signature scheme: 0x%04x", scheme)
	}

	// Prepare the credential for digital signing.
	hash := getHash(delegatorScheme)
	cred := &credential{validTime, pk, scheme}
	in, err := prepareDelegation(hash, cred, cert.Leaf.Raw, delegatorScheme, vers)
	if err != nil {
		return nil, nil, err
	}

	var sig []byte
	switch sk := cert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		opts := crypto.SignerOpts(hash)
		sig, err = sk.Sign(rand.Reader, in, opts)
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("unsupported delgation key type: %T", sk)
	}

	return &DelegatedCredential{
		ValidTime:       validTime,
		PublicKey:       pk,
		publicKeyScheme: scheme,
		Scheme:          delegatorScheme,
		Signature:       sig,
	}, sk, nil
}

// Validate checks that that the signature is valid, that the credential hasn't
// expired, and that the TTL is valid. It also checks that certificate can be
// used for delegation.
func (dc *DelegatedCredential) Validate(cert *x509.Certificate, vers uint16, now time.Time) (bool, error) {
	if !isValidForDelegation(cert) {
		return false, errNoDelegationUsage
	}

	if dc.IsExpired(cert.NotBefore, now) {
		return false, errors.New("credential has expired")
	}

	if dc.InvalidTTL(cert.NotBefore, now) {
		return false, errors.New("credential TTL is invalid")
	}

	hash := getHash(dc.Scheme)
	cred := &credential{dc.ValidTime, dc.PublicKey, dc.publicKeyScheme}
	in, err := prepareDelegation(hash, cred, cert.Raw, dc.Scheme, vers)
	if err != nil {
		return false, err
	}

	// TODO: Verify that expected_cert_verify_algorithm matches the scheme
	// indicated in the peer’s CertificateVerify message and that the
	// algorithm is allowed for use with delegated credentials.

	// TODO(any) This code overlaps signficantly with verifyHandshakeSignature()
	// in ../auth.go. This should be refactored.
	switch dc.Scheme {
	case ECDSAWithP256AndSHA256,
		ECDSAWithP384AndSHA384,
		ECDSAWithP521AndSHA512:
		pk, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return false, errors.New("expected ECDSA public key")
		}
		sig := new(ecdsaSignature)
		if _, err = asn1.Unmarshal(dc.Signature, sig); err != nil {
			return false, err
		}
		return ecdsa.Verify(pk, in, sig.R, sig.S), nil

	default:
		return false, fmt.Errorf(
			"unsupported signature scheme: 0x%04x", dc.Scheme)
	}
}

// Marshal encodes a DelegatedCredential structure per the spec. It also sets
// dc.Raw to the output as a side effect.
func (dc *DelegatedCredential) Marshal() ([]byte, error) {
	cred := &credential{dc.ValidTime, dc.PublicKey, dc.publicKeyScheme}
	serialized, err := cred.marshal()
	if err != nil {
		return nil, err
	}

	serializedScheme := make([]byte, 2)
	binary.BigEndian.PutUint16(serializedScheme, uint16(dc.Scheme))
	serialized = append(serialized, serializedScheme...)

	if len(dc.Signature) > dcMaxSignatureLen {
		return nil, errors.New("signature is too long")
	}
	serializedSignature := make([]byte, 2)
	binary.BigEndian.PutUint16(serializedSignature, uint16(len(dc.Signature)))
	serializedSignature = append(serializedSignature, dc.Signature...)
	serialized = append(serialized, serializedSignature...)

	dc.Raw = serialized
	return serialized, nil
}

// UnmarshalDelegatedCredential decodes a DelegatedCredential structure.
func UnmarshalDelegatedCredential(serialized []byte) (*DelegatedCredential, error) {
	// Get the length of the serialized credential that begins at the start of
	// the input slice.
	serializedCredentialLen, err := getCredentialLen(serialized)
	if err != nil {
		return nil, err
	}

	cred, err := unmarshalCredential(serialized[:serializedCredentialLen])
	if err != nil {
		return nil, err
	}

	serialized = serialized[serializedCredentialLen:]
	if len(serialized) < 4 {
		return nil, errors.New("delegated credential is too short")
	}
	scheme := SignatureScheme(binary.BigEndian.Uint16(serialized))

	serialized = serialized[2:]
	serializedSignatureLen := binary.BigEndian.Uint16(serialized)

	serialized = serialized[2:]
	if len(serialized) < int(serializedSignatureLen) {
		return nil, errors.New("signature of delegated credential is too short")
	}
	sig := serialized[:serializedSignatureLen]

	return &DelegatedCredential{
		ValidTime:       cred.validTime,
		PublicKey:       cred.publicKey,
		publicKeyScheme: cred.scheme,
		Scheme:          scheme,
		Signature:       sig,
	}, nil
}
