package tls

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestKemAPI(t *testing.T) {
	publicKey, privateKey, err := KemKeypair(rand.Reader, Kem25519)
	if err != nil {
		t.Error(err)
	}
	ss, ct, err := Encapsulate(rand.Reader, Kem25519, publicKey)
	if err != nil {
		t.Error(err)
	}

	ss2, err := Decapsulate(Kem25519, privateKey, ct)
	if err != nil || !bytes.Equal(ss, ss2) {
		t.FailNow()
	}
}
