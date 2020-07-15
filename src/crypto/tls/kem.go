package tls

import (
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

// KemID identifies the KEM we use
type KemID uint16

const (
	// Kem25519 is X25519 as a KEM
	Kem25519 KemID = 1
)

// KemKeypair generates a KemKeypair for a given KEM
// returns (public, private, err)
func KemKeypair(rand io.Reader, kemID KemID) ([]byte, []byte, error) {
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

	return publicKey, privateKey, nil
}

// Encapsulate returns (shared secret, ciphertext)
func Encapsulate(rand io.Reader, kemID KemID, publicKey []byte) ([]byte, []byte, error) {
	if kemID != Kem25519 {
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
	sharedSecret, err := curve25519.X25519(privateKey, publicKey)
	if err != nil {
		return nil, nil, err
	}

	return sharedSecret, ciphertext, nil
}

// Decapsulate generates the shared secret
func Decapsulate(kemID KemID, privateKey []byte, ciphertext []byte) ([]byte, error) {
	if kemID != Kem25519 {
		return nil, errors.New("tls: internal error: unsupported KEM")
	}

	sharedSecret, err := curve25519.X25519(privateKey, ciphertext)
	if err != nil {
		return nil, err
	}

	return sharedSecret, nil
}
