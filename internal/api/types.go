package api

import (
	"encoding/hex"
	"golang.org/x/crypto/sha3"
	"hash"
)

const HashLength = 32

type Hash [HashLength]byte

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
