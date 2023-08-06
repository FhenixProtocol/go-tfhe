package api

import "C"
import (
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

func NewCipherText(value big.Int, t UintType) (*Ciphertext, error) {

	res, err := Encrypt(value, t)
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
		UintType:      t,
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
	}, nil
}

func NewCipherTextFromBytes(ctBytes []byte, t UintType) (*Ciphertext, error) {

	//if len(ctBytes) != expected len
	// cry

	return &Ciphertext{
		Serialization: ctBytes,
		UintType:      t,
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
	}, nil
}

//func NewCipherTextWithKey(value big.Int, sks []byte, t api.FheUintType) (*Ciphertext, error) {
//
//	res, err := api.Encrypt(value, 0)
//	if err != nil {
//		return nil, err
//	}
//
//	return &Ciphertext{
//		Serialization: res,
//	}, nil
//}

func (ct *Ciphertext) IsRandom() bool {
	return ct.random
}

func (ct *Ciphertext) Add(rhs *Ciphertext) (*Ciphertext, error) {

	if ct.UintType != rhs.UintType {
		return nil, fmt.Errorf("cannot add uints of different types")
	}

	res, err := Add(ct.Serialization, rhs.Serialization, uint8(ct.UintType))
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
	}, nil
}

func (ct *Ciphertext) Decrypt() (*big.Int, error) {
	return big.NewInt(0), nil
}

func (ct *Ciphertext) Sub(rhs *Ciphertext) (*Ciphertext, error) {
	if ct.UintType != rhs.UintType {
		return nil, fmt.Errorf("cannot subtract uints of different types")
	}

	res, err := Sub(ct.Serialization, rhs.Serialization, uint8(ct.UintType))
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
	}, nil
}

func (ct *Ciphertext) Mul(rhs *Ciphertext) (*Ciphertext, error) {
	if ct.UintType != rhs.UintType {
		return nil, fmt.Errorf("cannot multiply uints of different types")
	}

	res, err := Mul(ct.Serialization, rhs.Serialization, uint8(ct.UintType))
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
	}, nil
}

func (ct *Ciphertext) Lt(rhs *Ciphertext) (*Ciphertext, error) {
	if ct.UintType != rhs.UintType {
		return nil, fmt.Errorf("cannot compare uints of different types")
	}

	res, err := Lt(ct.Serialization, rhs.Serialization, uint8(ct.UintType))
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
	}, nil
}

func (ct *Ciphertext) Lte(rhs *Ciphertext) (*Ciphertext, error) {
	if ct.UintType != rhs.UintType {
		return nil, fmt.Errorf("cannot compare uints of different types")
	}

	res, err := Lte(ct.Serialization, rhs.Serialization, uint8(ct.UintType))
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
	}, nil
}
