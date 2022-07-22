package learn_go_ssh_key_verify

import (
	"crypto/rand"
	"golang.org/x/crypto/ssh"
)

// validator
type publicKeyValidator struct {
	publicKey ssh.PublicKey
}

func NewPublicKeyValidator(key []byte) (*publicKeyValidator, error) {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(key)
	if err != nil {
		return nil, err
	}
	return &publicKeyValidator{publicKey: publicKey}, nil
}

func (p *publicKeyValidator) Verify(data []byte, sig *ssh.Signature) error {
	return p.publicKey.Verify(data, sig)
}

// signer
type privateKeySigner struct {
	singer ssh.Signer
}

func NewPrivateKeySigner(key []byte) (*privateKeySigner, error) {
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &privateKeySigner{singer: signer}, nil
}

func (p *privateKeySigner) Sign(data []byte) (*ssh.Signature, error) {
	return p.singer.Sign(rand.Reader, data)
}
