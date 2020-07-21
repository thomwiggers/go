package tls

import (
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

// KemID identifies the KEM we use
type KemID = CurveID

const (
	// Kem25519 is X25519 as a KEM
	Kem25519 KemID = 0x01fb
	// CSIDH is a post-quantum NIKE
	CSIDH KemID = 0x01fc
	// Kyber512 is a post-quantum KEM based on MLWE
	Kyber512 KemID = 0x01fd
)

type kemPrivateKey struct {
	id         KemID
	privateKey []byte
}

type kemPublicKey struct {
	id        KemID
	publicKey []byte
}

func (c CurveID) isKem() bool {
	switch KemID(c) {
	case Kem25519, CSIDH, Kyber512:
		return true
	}
	return false
}

// KemKeypair generates a KemKeypair for a given KEM
// returns (public, private, err)
func KemKeypair(rand io.Reader, kemID KemID) (*kemPublicKey, *kemPrivateKey, error) {
	if kemID != Kem25519 {
		return nil, nil, errors.New("tls: internal error: unsupported KEM")
	}

	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(rand, privateKey); err != nil {
		return nil, nil, err
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return &kemPublicKey{id: kemID, publicKey: publicKey}, &kemPrivateKey{id: kemID, privateKey: privateKey}, nil
}

// Encapsulate returns (shared secret, ciphertext)
func Encapsulate(rand io.Reader, pk kemPublicKey) ([]byte, []byte, error) {
	if pk.id != Kem25519 {
		return nil, nil, errors.New("tls: internal error: unsupported KEM")
	}

	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(rand, privateKey); err != nil {
		return nil, nil, err
	}
	ciphertext, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	sharedSecret, err := curve25519.X25519(privateKey, pk.publicKey)
	if err != nil {
		return nil, nil, err
	}

	return sharedSecret, ciphertext, nil
}

// Decapsulate generates the shared secret
func Decapsulate(privateKey kemPrivateKey, ciphertext []byte) ([]byte, error) {
	if privateKey.id != Kem25519 {
		return nil, errors.New("tls: internal error: unsupported KEM")
	}

	sharedSecret, err := curve25519.X25519(privateKey.privateKey, ciphertext)
	if err != nil {
		return nil, err
	}

	return sharedSecret, nil
}
