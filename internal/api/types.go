package api

// #include "bindings.h"
import "C"
import (
	"encoding/hex"
	"golang.org/x/crypto/sha3"
	"hash"
)

type UintType uint32

const (
	Uint8  UintType = C.FheUintType_Uint8
	Uint16 UintType = C.FheUintType_Uint16
	Uint32 UintType = C.FheUintType_Uint32
)

const HashLength = 32

type Hash [HashLength]byte

func (ct *Ciphertext) Hash() Hash {

	if ct.hash == nil {
		// cache
		ct.hash = Keccak256(ct.Serialization)
	}

	var h Hash
	h.SetBytes(ct.hash)
	return h
}

func BytesToHash(b []byte) Hash {
	var h Hash
	h.SetBytes(b)
	return h
}

func (h *Hash) SetBytes(b []byte) {
	if len(b) > len(h) {
		b = b[len(b)-HashLength:]
	}

	copy(h[HashLength-len(b):], b)
}

func (h Hash) Hex() string {
	return hex.EncodeToString(h[:])
}

// Keccak256 calculates and returns the Keccak256 hash of the input data.
func Keccak256(data ...[]byte) []byte {
	b := make([]byte, 32)
	d := NewKeccakState()
	for _, b := range data {
		d.Write(b)
	}
	d.Sum(b)
	return b
}

// NewKeccakState creates a new KeccakState
func NewKeccakState() hash.Hash {
	return sha3.NewLegacyKeccak256()
}
