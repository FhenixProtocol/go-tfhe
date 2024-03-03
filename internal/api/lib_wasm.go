package api

import (
	"math/big"

	"github.com/fhenixprotocol/go-tfhe/internal/api/wasm"
)

func mathOperation(lhs []byte, rhs []byte, uintType uint8, op uint32) ([]byte, error) {
	return wasm.MathOperation(lhs, rhs, uintType, wasm.OperationType(op))
}

func unaryMathOperation(lhs []byte, uintType uint8, op uint32) ([]byte, error) {
	return wasm.UnaryMathOperation(lhs, uintType, wasm.OperationType(op))
}

func castOperation(val []byte, fromType uint8, toType uint8) ([]byte, error) {
	return wasm.CastOperation(val, fromType, toType)
}

func cmux(control []byte, ifTrue []byte, ifFalse []byte, uintType uint8) ([]byte, error) {
	return wasm.Cmux(control, ifTrue, ifFalse, uintType)
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

func GenerateFheKeys(clientKeyPath string, serverKeyPath string, publicKeyPath string) error {
	return wasm.GenerateFheKeys(clientKeyPath, serverKeyPath, publicKeyPath)
}

func LibTfheVersion() string {
	return "wasm"
}

func InitLogger() {
	wasm.InitLogger()
}
