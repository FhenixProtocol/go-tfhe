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

func GenerateFheKeys() {
	err := tfhelib.GenerateFheKeys("./", "sks", "cks", "pks")
	if err != nil {
		panic(err)
	}
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

	resp, err := ct.Decrypt()

	if resp != bigInt.Add(bigInt, bigInt) {
		return fmt.Errorf("no beuno: %v vs %v * 2", resp, bigInt)
	}

	println("Success")
	return nil
}

func main() {
	GenerateFheKeys()
	println("done generating keys")
	err := Add()
	if err != nil {
		panic(err)
	}
}
