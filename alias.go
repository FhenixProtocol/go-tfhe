package tfhe

import (
	"github.com/fhenixprotocol/go-tfhe/internal/api"
	"github.com/fhenixprotocol/go-tfhe/internal/oracle"
)

// Types
type (
	Ciphertext = api.Ciphertext
	UintType   = api.UintType
	Hash       = api.Hash
	Config     = api.Config
)

// Const
const (
	Uint8  = api.Uint8
	Uint16 = api.Uint16
	Uint32 = api.Uint32
)

// Function
var (
	NewCipherText          = api.NewCipherText
	NewCipherTextTrivial   = api.NewCipherTextTrivial
	BytesToHash            = api.BytesToHash
	NewCipherTextFromBytes = api.NewCipherTextFromBytes
	oracleStorage          = oracle.OracleInterface
	ConfigDefault          = api.ConfigDefault
)
