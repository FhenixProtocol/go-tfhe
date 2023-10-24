package wasm_cmd

import (
	"fmt"
	tfhelib "github.com/fhenixprotocol/go-tfhe"
	"math/big"
)

func Version() error {
	libtfheVersion := tfhelib.Version()
	fmt.Printf("Tfhe-rs version: %d\n", libtfheVersion)
	return nil
}

func LoadFheKeys() {

}

func Add() error {
	bigInt := big.NewInt(10)
	ct, err := tfhelib.NewCipherText(*bigInt, tfhelib.Uint32, false)
	if err != nil {
		return err
	}

	ct2, err := tfhelib.NewCipherText(*bigInt, tfhelib.Uint32, false)
	if err != nil {
		return err
	}

	_, err = ct.Add(ct2)
	if err != nil {
		return err
	}

	// todo: decrypt

	return nil
}

func main() {
	Add()
}
