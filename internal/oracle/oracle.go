package oracle

import (
	"encoding/hex"
	"fmt"
	"github.com/fhenixprotocol/go-tfhe/internal/api"
)

// So we can generalize this into a local oracle (and less config), etc.
var OracleInterface Oracle

type dbRequireMessage struct {
	Value bool `json:"value"`
}
type dbDecryptMessage struct {
	Value string `json:"value"`
}

func requireKey(ciphertext []byte) string {
	// Take the Keccak256 and remove the leading 0x.
	return hex.EncodeToString(api.Keccak256(ciphertext))[2:]
}
func decryptKey(ciphertext []byte) string {
	// Take the Keccak256 and remove the leading 0x.
	return fmt.Sprintf("decrypt%s", hex.EncodeToString(api.Keccak256(ciphertext))[2:])
}

type Oracle interface {
	GetRequire(ct *api.Ciphertext) (bool, error)
	Decrypt(ct *api.Ciphertext) (string, error)
	PutRequire(ct *api.Ciphertext, decryptedNotZero bool) error
	Close()
}
