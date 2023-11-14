package api

import (
	"crypto/ed25519"
	"encoding/hex"
)

// TODO: Leaving this here, but assuming it's not going to be used?
func SignRequire(ciphertext []byte, value bool) string {
	b := RequireBytesToSign(ciphertext, value)
	signature := ed25519.Sign(KeyRequirePrivate, b)
	return hex.EncodeToString(signature)
}

func RequireBytesToSign(ciphertext []byte, value bool) []byte {
	// TODO: avoid copy
	b := make([]byte, 0, len(ciphertext)+1)
	b = append(b, ciphertext...)
	if value {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	return b
}

// TODO: is this used for anything?
func VerifyRequireSignature(message []byte, signature []byte) bool {
    pk, err := GetPublicKey()
    if err != nil {
        return false
    }
	return ed25519.Verify(pk, message, signature)
}