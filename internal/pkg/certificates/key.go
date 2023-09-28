package certificates

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// KeyPair represents a public/private key pair
type KeyPair struct {
	PublicKey  string
	PrivateKey string
	key        *rsa.PrivateKey
}

// Key returns the RSA private key for this private key pair
func (keyPair *KeyPair) Key() *rsa.PrivateKey {
	return keyPair.key
}

func newPrivateKey(keyBitSize int) (*KeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, keyBitSize)
	if err != nil {
		return nil, fmt.Errorf("cannot create private key: %w", err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal public key: %w", err)
	}
	publicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(publicKeyPEM, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKey,
	})
	if err != nil {
		return nil, fmt.Errorf("cannot encode public key: %w", err)
	}
	privateKeyPEM := new(bytes.Buffer)
	err = pem.Encode(privateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err != nil {
		return nil, fmt.Errorf("cannot encode private key: %w", err)
	}
	return &KeyPair{
		PublicKey:  publicKeyPEM.String(),
		PrivateKey: privateKeyPEM.String(),
		key:        key,
	}, nil
}
