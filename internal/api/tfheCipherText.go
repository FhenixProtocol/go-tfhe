package api

import "C"
import (
	"bytes"
	"fmt"
	"math/big"
)

type Ciphertext struct {
	//ptr           unsafe.Pointer
	Serialization []byte
	hash          []byte
	value         *big.Int
	random        bool
	UintType      UintType
}

func isZero(data []byte) bool {
	return bytes.Count(data, []byte{0}) == len(data)
}

func (ct *Ciphertext) Hash() Hash {

	if ct.hash == nil || isZero(ct.hash) {
		ct.hash = Keccak256(ct.Serialization)
	}

	var h Hash
	h.SetBytes(ct.hash)
	return h
}

func NewCipherText(value big.Int, t UintType, compact bool) (*Ciphertext, error) {
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

func NewCipherTextFromBytes(ctBytes []byte, t UintType, compact bool) (*Ciphertext, error) {

	//if len(ctBytes) != expected len
	// cry
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

func NewRandomCipherText(t UintType) (*Ciphertext, error) {

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

func (ct *Ciphertext) IsRandom() bool {
	return ct.random
}

func (ct *Ciphertext) Add(rhs *Ciphertext) (*Ciphertext, error) {

	if ct.UintType != rhs.UintType {
		return nil, fmt.Errorf("cannot add uints of different types")
	}

	res, err := mathOperation(ct.Serialization, rhs.Serialization, uint8(ct.UintType), add)
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
		hash:          Keccak256(res),
		UintType:      ct.UintType,
	}, nil
}

func (ct *Ciphertext) Decrypt() (*big.Int, error) {
	res, err := Decrypt(ct.Serialization, ct.UintType)
	return big.NewInt(int64(res)), err
}

func (ct *Ciphertext) Sub(rhs *Ciphertext) (*Ciphertext, error) {
	if ct.UintType != rhs.UintType {
		return nil, fmt.Errorf("cannot subtract uints of different types")
	}

	res, err := mathOperation(ct.Serialization, rhs.Serialization, uint8(ct.UintType), sub)
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
		UintType:      ct.UintType,
	}, nil
}

func (ct *Ciphertext) Mul(rhs *Ciphertext) (*Ciphertext, error) {
	if ct.UintType != rhs.UintType {
		return nil, fmt.Errorf("cannot multiply uints of different types")
	}

	res, err := mathOperation(ct.Serialization, rhs.Serialization, uint8(ct.UintType), mul)
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
		UintType:      ct.UintType,
	}, nil
}

func (ct *Ciphertext) Lt(rhs *Ciphertext) (*Ciphertext, error) {
	if ct.UintType != rhs.UintType {
		return nil, fmt.Errorf("cannot compare uints of different types")
	}

	res, err := mathOperation(ct.Serialization, rhs.Serialization, uint8(ct.UintType), lt)
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
		UintType:      ct.UintType,
	}, nil
}

func (ct *Ciphertext) Lte(rhs *Ciphertext) (*Ciphertext, error) {
	if ct.UintType != rhs.UintType {
		return nil, fmt.Errorf("cannot compare uints of different types")
	}

	res, err := mathOperation(ct.Serialization, rhs.Serialization, uint8(ct.UintType), lte)
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
		UintType:      ct.UintType,
	}, nil
}
