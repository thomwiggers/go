package tls

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestKemAPI(t *testing.T) {
	tests := []struct {
		name string
		kem  KemID
	}{
		{"Kem25519", Kem25519},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publicKey, privateKey, err := Keypair(rand.Reader, tt.kem)
			if err != nil {
				t.Error(err)
			}
			ss, ct, err := Encapsulate(rand.Reader, &publicKey)
			if err != nil {
				t.Error(err)
			}

			ss2, err := Decapsulate(&privateKey, ct)
			if err != nil || !bytes.Equal(ss, ss2) {
				t.FailNow()
			}
		})
	}
}
