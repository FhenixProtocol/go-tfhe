package api

import (
	"github.com/fhenixprotocol/go-tfhe/internal/api/wasm"
	"math/big"
)

// For now track this in a global, but this is kind of messy
var LoadKeysDone bool
var KeyRequirePublic []byte
var KeyRequirePrivate []byte

var CKS []byte
var PKS []byte
var SKS []byte

const (
	Uint8  UintType = 0
	Uint16 UintType = 1
	Uint32 UintType = 2
)

const (
	add uint32 = 0
	sub        = 1
	mul        = 2
	lt         = 3
	lte        = 4
)

type UintType uint32

func mathOperation(lhs []byte, rhs []byte, uintType uint8, op uint32) ([]byte, error) {
	return wasm.MathOperation(lhs, rhs, uintType, wasm.OperationType(op))
}

func DeserializeServerKey(serverKeyBytes []byte) (bool, error) {
	return wasm.DeserializeServerKey(serverKeyBytes)

}

func DeserializeClientKey(clientKeyBytes []byte) (bool, error) {
	return wasm.DeserializeClientKey(clientKeyBytes)
}

func DeserializePublicKey(publicKeyBytes []byte) (bool, error) {
	return wasm.DeserializePublicKey(publicKeyBytes)

}

func GetPublicKey() ([]byte, error) {
	return wasm.GetPublicKey()
}

func Encrypt(value big.Int, intType UintType) ([]byte, error) {
	return wasm.Encrypt(value, wasm.UintType(intType))
}

func EncryptTrivial(value big.Int, intType UintType) ([]byte, error) {
	return wasm.EncryptTrivial(value, wasm.UintType(intType))
}

func ExpandCompressedValue(cipherText []byte, intType UintType) ([]byte, error) {
	return wasm.ExpandCompressedValue(cipherText, wasm.UintType(intType))
}

func Decrypt(cipherText []byte, intType UintType) (uint64, error) {
	return wasm.Decrypt(cipherText, wasm.UintType(intType))
}

func SignRequire(ciphertext []byte, value bool) string {
	return wasm.SignRequire(ciphertext, value)
}

func RequireBytesToSign(ciphertext []byte, value bool) []byte {
	return wasm.RequireBytesToSign(ciphertext, value)
}

func VerifyRequireSignature(message []byte, signature []byte) bool {
	return wasm.VerifyRequireSignature(message, signature)
}

func GenerateFheKeys(clientKeyPath string, serverKeyPath string, publicKeyPath string) error {
	return wasm.GenerateFheKeys(clientKeyPath, serverKeyPath, publicKeyPath)
}

func LibTfheVersion() uint32 {
	return wasm.LibTfheVersion()
}
