package tfhe

import (
	"github.com/fhenixprotocol/go-tfhe/internal/api"
	"github.com/fhenixprotocol/go-tfhe/internal/oracle"
)

// Types
type (
	// Ciphertext Represents a TFHE ciphertext.
	//
	// Once a ciphertext has a value (either from deserialization, encryption or makeRandom()),
	// it must not be set another value. If that is needed, a new ciphertext must be created.
	// todo (Itzik): Testing whether or not passing the serialized data and not the raw pointer.
	// Obviously it will come at a performance cost, but possibly the security/clarity of the code during the
	// early days could be worth it? For the part seems serialization of FHEu8 is about 20us
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

	InitLogger    = api.InitLogger
	oracleStorage = oracle.OracleInterface
)
