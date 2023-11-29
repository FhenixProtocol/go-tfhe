package api

import (
	"math/big"
	"strconv"

	"github.com/fhenixprotocol/go-tfhe/internal/api/amd64"
)

func mathOperation(lhs []byte, rhs []byte, uintType uint8, op uint32) ([]byte, error) {
	return amd64.MathOperation(lhs, rhs, uintType, amd64.OperationType(op))
}

func castOperation(val []byte, fromType uint8, toType uint8) ([]byte, error) {
	return amd64.CastOperation(val, fromType, toType)
}

func cmux(control []byte, ifTrue []byte, ifFalse []byte, uintType uint8) ([]byte, error) {
	return amd64.Cmux(control, ifTrue, ifFalse, uintType)
}

func DeserializeServerKey(serverKeyBytes []byte) (bool, error) {
	return amd64.DeserializeServerKey(serverKeyBytes)

}

func DeserializeClientKey(clientKeyBytes []byte) (bool, error) {
	return amd64.DeserializeClientKey(clientKeyBytes)

}

func DeserializePublicKey(publicKeyBytes []byte) (bool, error) {
	return amd64.DeserializePublicKey(publicKeyBytes)

}

func GetPublicKey() ([]byte, error) {
	return amd64.GetPublicKey()
}

func Encrypt(value big.Int, intType UintType) ([]byte, error) {
	return amd64.Encrypt(value, amd64.UintType(intType))
}

func EncryptTrivial(value big.Int, intType UintType) ([]byte, error) {
	return amd64.EncryptTrivial(value, amd64.UintType(intType))
}

func ExpandCompressedValue(cipherText []byte, intType UintType) ([]byte, error) {
	return amd64.ExpandCompressedValue(cipherText, amd64.UintType(intType))
}

func Decrypt(cipherText []byte, intType UintType) (uint64, error) {
	return amd64.Decrypt(cipherText, amd64.UintType(intType))
}

func GenerateFheKeys(clientKeyPath string, serverKeyPath string, publicKeyPath string) error {
	return amd64.GenerateFheKeys(clientKeyPath, serverKeyPath, publicKeyPath)
}

func LibTfheVersion() uint32 {
	result, err := amd64.LibTfheVersion()

	if err != nil {
		panic(err)
	}

	asInt, err := strconv.ParseInt(result, 10, 32)
	if err != nil {
		panic(err)
	}

	return uint32(asInt)
}
