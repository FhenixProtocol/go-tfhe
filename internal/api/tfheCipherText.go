package api

import (
	"bytes"
	"fmt"
	"math/big"
)

// Ciphertext represents the encrypted data structure.
type Ciphertext struct {
	Serialization []byte   // Serialized representation of the ciphertext
	hash          []byte   // Keccak256 hash of the serialized data
	value         *big.Int // Big int representation of the encrypted value (for internal use)
	random        bool     // Flag to indicate if the ciphertext is generated randomly
	UintType      UintType // Type of the unsigned integer (for example, uint8, uint16, etc.)
}

// isZero checks if a byte slice contains all zero bytes.
func isZero(data []byte) bool {
	return bytes.Count(data, []byte{0}) == len(data)
}

// Hash calculates and returns the hash of the serialized ciphertext.
func (ct *Ciphertext) Hash() Hash {
	// If hash is not already calculated, calculate it
	if ct.hash == nil || isZero(ct.hash) {
		ct.hash = Keccak256(ct.Serialization)
	}

	var h Hash
	h.SetBytes(ct.hash)
	return h
}

// NewCipherText creates a new Ciphertext instance with encryption of the provided value.
func NewCipherText(value big.Int, t UintType, compact bool) (*Ciphertext, error) {
	// Perform encryption, potentially expanding the result if compact is false
	res, err := Encrypt(value, t)
	if err != nil {
		return nil, err
	}

	if !compact {
		res, err = ExpandCompressedValue(res, t)
		if err != nil {
			return nil, err
		}

		return &Ciphertext{
			Serialization: res,
			UintType:      t,
			hash:          Keccak256(res),
		}, nil
	}

	return &Ciphertext{
		Serialization: res,
		UintType:      t,
		hash:          Keccak256(res),
	}, nil
}

// NewCipherTextTrivial creates a new Ciphertext using trivial encryption - trivial encryption is used to encrypt "public" constants to
// inject into FHE operations
func NewCipherTextTrivial(value big.Int, t UintType) (*Ciphertext, error) {

	res, err := EncryptTrivial(value, t)
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
		UintType:      t,
		hash:          Keccak256(res),
	}, nil
}

// NewCipherTextFromBytes creates a new Ciphertext from its byte representation.
func NewCipherTextFromBytes(ctBytes []byte, t UintType, compact bool) (*Ciphertext, error) {

	// Validate and potentially expand the ciphertext bytes
	if compact {
		res, err := ExpandCompressedValue(ctBytes, t)
		if err != nil {
			return nil, err
		}

		return &Ciphertext{
			Serialization: res,
			UintType:      t,
			hash:          Keccak256(res),
		}, nil
	}

	return &Ciphertext{
		Serialization: ctBytes,
		UintType:      t,
		hash:          Keccak256(ctBytes),
	}, nil
}

// NewRandomCipherText creates a random Ciphertext - only not really. It's just used for simulations and testing, so we inject some
// constant value here instead of an actual random
func NewRandomCipherText(t UintType) (*Ciphertext, error) {
	// Not really though!
	res, err := Encrypt(*big.NewInt(int64(5)), t)
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
		UintType:      t,
		random:        true,
		hash:          Keccak256(res),
	}, nil
}

// IsRandom checks if the ciphertext was randomly generated - this is used for gas simulation
func (ct *Ciphertext) IsRandom() bool {
	return ct.random
}

// Decrypt decrypts the ciphertext and returns the plaintext value.
func (ct *Ciphertext) Decrypt() (*big.Int, error) {
	res, err := Decrypt(ct.Serialization, ct.UintType)
	return big.NewInt(int64(res)), err
}

func (ct *Ciphertext) performOperation(rhs *Ciphertext, operation uint32) (*Ciphertext, error) {
	if ct.UintType != rhs.UintType {
		return nil, fmt.Errorf("cannot perform operation on uints of different types")
	}

	res, err := mathOperation(ct.Serialization, rhs.Serialization, uint8(ct.UintType), operation)
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
		hash:          Keccak256(res),
		UintType:      ct.UintType,
	}, nil
}

func (ct *Ciphertext) performUnaryOperation(operation uint32) (*Ciphertext, error) {
	res, err := unaryMathOperation(ct.Serialization, uint8(ct.UintType), operation)
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
		hash:          Keccak256(res),
		UintType:      ct.UintType,
	}, nil
}

// Now you can use the above function to implement the original methods:

// Add performs ciphertext addition.
func (ct *Ciphertext) Add(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performOperation(rhs, add)
}

func (ct *Ciphertext) Sub(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performOperation(rhs, sub)
}

func (ct *Ciphertext) Mul(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performOperation(rhs, mul)
}

func (ct *Ciphertext) Lt(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performOperation(rhs, lt)
}

func (ct *Ciphertext) Lte(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performOperation(rhs, lte)
}

func (ct *Ciphertext) Div(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performOperation(rhs, div)
}

func (ct *Ciphertext) Gt(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performOperation(rhs, gt)
}

func (ct *Ciphertext) Gte(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performOperation(rhs, gte)
}

func (ct *Ciphertext) Rem(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performOperation(rhs, rem)
}

func (ct *Ciphertext) And(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performOperation(rhs, and)
}

func (ct *Ciphertext) Or(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performOperation(rhs, or)
}

func (ct *Ciphertext) Xor(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performOperation(rhs, xor)
}

func (ct *Ciphertext) Eq(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performOperation(rhs, eq)
}

func (ct *Ciphertext) Ne(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performOperation(rhs, ne)
}

func (ct *Ciphertext) Min(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performOperation(rhs, min)
}

func (ct *Ciphertext) Max(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performOperation(rhs, max)
}

func (ct *Ciphertext) Shl(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performOperation(rhs, shl)
}

func (ct *Ciphertext) Shr(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performOperation(rhs, shr)
}

func (ct *Ciphertext) Not() (*Ciphertext, error) {
	return ct.performUnaryOperation(not)
}

// todo add more ops
