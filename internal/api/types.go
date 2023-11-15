package api

import (
	"encoding/hex"
	"golang.org/x/crypto/sha3"
	"hash"
)

const (
	Uint8  UintType = 0
	Uint16 UintType = 1
	Uint32 UintType = 2
)

// For now track this in a global, but this is kind of messy
var LoadKeysDone bool
var KeyRequirePublic []byte
var KeyRequirePrivate []byte

var CKS []byte
var PKS []byte
var SKS []byte

const (
	add uint32 = 0
	sub        = 1
	mul        = 2
	lt         = 3
	lte        = 4
	div        = 5
	gt         = 6
	gte        = 7
	// todo add more ops
)

type UintType uint32

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
	d := NewKeccakState()
	for _, datum := range data {
		d.Write(datum)
	}
	return d.Sum(nil)
}

// NewKeccakState creates a new KeccakState
func NewKeccakState() hash.Hash {
	return sha3.NewLegacyKeccak256()
}
