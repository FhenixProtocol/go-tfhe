package oracle

import (
	"github.com/fhenixprotocol/go-tfhe/internal/api"
)

// So we can generalize this into a local oracle (and less config), etc.
var OracleInterface Oracle

type Oracle interface {
	GetRequire(ct *api.Ciphertext) (bool, error)
	PutRequire(ct *api.Ciphertext, decryptedNotZero bool) error
	Close()
}
