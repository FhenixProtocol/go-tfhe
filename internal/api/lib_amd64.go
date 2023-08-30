package api

import (
	"github.com/fhenixprotocol/go-tfhe/internal/api/amd64"
	"math/big"
	"strconv"
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
)

type UintType uint32

func mathOperation(lhs []byte, rhs []byte, uintType uint8, op uint32) ([]byte, error) {
	return amd64.MathOperation(lhs, rhs, uintType, op)
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

func SignRequire(ciphertext []byte, value bool) string {
	return amd64.SignRequire(ciphertext, value)
}

func RequireBytesToSign(ciphertext []byte, value bool) []byte {
	return amd64.RequireBytesToSign(ciphertext, value)
}

func VerifyRequireSignature(message []byte, signature []byte) bool {
	return amd64.VerifyRequireSignature(message, signature)
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
