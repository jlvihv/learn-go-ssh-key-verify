package learn_go_ssh_key_verify

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFunc(t *testing.T) {
	authStr := "verify me"

	// sign
	prv, err := NewPrivateKeySigner(readKey("prv"))
	if err != nil {
		panic(err)
	}
	sign, err := prv.Sign([]byte(authStr))
	if err != nil {
		panic(err)
	}

	// verify
	pub, err := NewPublicKeyValidator(readKey("pub"))
	if err != nil {
		panic(err)
	}
	err = pub.Verify([]byte(authStr), sign)
	if err != nil {
		t.Errorf("verify failed: %v", err)
	}
}

// 'pub' or 'prv'
func readKey(str string) []byte {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	pubKeyPath := filepath.Join(homeDir, ".ssh", "id_ed25519.pub")
	prvKeyPath := filepath.Join(homeDir, ".ssh", "id_ed25519")
	switch str {
	case "pub":
		pubKeyBytes, err := os.ReadFile(pubKeyPath)
		if err != nil {
			panic(err)
		}
		return pubKeyBytes
	case "prv":
		prvKeyBytes, err := os.ReadFile(prvKeyPath)
		if err != nil {
			panic(err)
		}
		return prvKeyBytes
	default:
		panic("invalid key type")
	}
}
