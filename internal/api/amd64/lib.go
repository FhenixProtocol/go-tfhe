//go:build cgo

package amd64

// #include <stdlib.h>
// #include "bindings.h"
import "C"
import (
	"fmt"
	"go/types"
	"math/big"
	"runtime"
	"syscall"
	"unsafe"
)

type UintType uint32

const (
	Uint8  UintType = C.FheUintType_Uint8
	Uint16 UintType = C.FheUintType_Uint16
	Uint32 UintType = C.FheUintType_Uint32
)

// Value types
type (
	cint   = C.int
	cbool  = C.bool
	cusize = C.size_t
	// cu8    = C.uint8_t
	// cu32   = C.uint32_t
	cu64 = C.uint64_t
	// ci8    = C.int8_t
	ci32 = C.int32_t
	// ci64   = C.int64_t
)

type OperationType C.Op

const (
	add OperationType = C.Op_Add
	sub               = C.Op_Sub
	mul               = C.Op_Mul
	lt                = C.Op_Lt
	lte               = C.Op_Lte
	// todo why is this here?
)

// Pointers
type (
	cu8_ptr = *C.uint8_t
)

func MathOperation(lhs []byte, rhs []byte, uintType uint8, op OperationType) ([]byte, error) {
	errmsg := uninitializedUnmanagedVector()

	num1 := makeView(lhs)
	defer runtime.KeepAlive(num1)

	num2 := makeView(rhs)
	defer runtime.KeepAlive(num2)

	res, err := C.math_operation(num1, num2, ci32(op), C.FheUintType(uintType), &errmsg)
	if err != nil {
		return nil, errorWithMessage(err, errmsg)
	}

	return copyAndDestroyUnmanagedVector(res), nil
}

func CastOperation(val []byte, fromType uint8, toType uint8) ([]byte, error) {
	errmsg := uninitializedUnmanagedVector()

	valView := makeView(val)
	defer runtime.KeepAlive(valView)

	res, err := C.cast_operation(valView, C.FheUintType(fromType), C.FheUintType(toType), &errmsg)
	if err != nil {
		return nil, errorWithMessage(err, errmsg)
	}

	return copyAndDestroyUnmanagedVector(res), nil
}

func Cmux(control []byte, ifTrue []byte, ifFalse []byte, uintType uint8) ([]byte, error) {
	errmsg := uninitializedUnmanagedVector()

	con := makeView(control)
	defer runtime.KeepAlive(control)

	t := makeView(ifTrue)
	defer runtime.KeepAlive(t)

	f := makeView(ifFalse)
	defer runtime.KeepAlive(f)

	res, err := C.cmux(con, t, f, C.FheUintType(uintType), &errmsg)
	if err != nil {
		return nil, errorWithMessage(err, errmsg)
	}

	return copyAndDestroyUnmanagedVector(res), nil
}

func DeserializeServerKey(serverKeyBytes []byte) (bool, error) {

	sks := makeView(serverKeyBytes)
	defer runtime.KeepAlive(sks)

	errmsg := uninitializedUnmanagedVector()

	_, err := C.load_server_key(sks, &errmsg)
	if err != nil {
		return false, errorWithMessage(err, errmsg)
	}
	return true, nil
}

func DeserializeClientKey(clientKeyBytes []byte) (bool, error) {

	clientKeyView := makeView(clientKeyBytes)
	defer runtime.KeepAlive(clientKeyView)

	errmsg := uninitializedUnmanagedVector()

	_, err := C.load_client_key(clientKeyView, &errmsg)
	if err != nil {
		return false, errorWithMessage(err, errmsg)
	}
	return true, nil
}

func DeserializePublicKey(publicKeyBytes []byte) (bool, error) {

	publicKeyView := makeView(publicKeyBytes)
	defer runtime.KeepAlive(publicKeyView)

	errmsg := uninitializedUnmanagedVector()

	_, err := C.load_public_key(publicKeyView, &errmsg)
	if err != nil {
		return false, errorWithMessage(err, errmsg)
	}
	return true, nil
}

func GetPublicKey() ([]byte, error) {
	errmsg := uninitializedUnmanagedVector()

	res := C.UnmanagedVector{}
	res, err := C.get_public_key(&errmsg)
	if err != nil {
		return nil, errorWithMessage(err, errmsg)
	}

	return copyAndDestroyUnmanagedVector(res), nil
}

func Encrypt(value big.Int, intType UintType) ([]byte, error) {
	val := value.Uint64()

	errmsg := uninitializedUnmanagedVector()

	res, err := C.encrypt(cu64(val), C.FheUintType(intType), &errmsg)
	if err != nil {
		return nil, errorWithMessage(err, errmsg)
	}

	return copyAndDestroyUnmanagedVector(res), nil
}

func EncryptTrivial(value big.Int, intType UintType) ([]byte, error) {
	val := value.Uint64()

	errmsg := uninitializedUnmanagedVector()

	res, err := C.trivial_encrypt(cu64(val), C.FheUintType(intType), &errmsg)
	if err != nil {
		return nil, errorWithMessage(err, errmsg)
	}

	return copyAndDestroyUnmanagedVector(res), nil

}

func ExpandCompressedValue(cipherText []byte, intType UintType) ([]byte, error) {
	ctView := makeView(cipherText)
	defer runtime.KeepAlive(ctView)
	errmsg := uninitializedUnmanagedVector()

	res, err := C.expand_compressed(ctView, C.FheUintType(intType), &errmsg)
	if err != nil {
		return nil, errorWithMessage(err, errmsg)
	}

	return copyAndDestroyUnmanagedVector(res), nil

}

func Decrypt(cipherText []byte, intType UintType) (uint64, error) {
	ctView := makeView(cipherText)
	defer runtime.KeepAlive(ctView)

	errmsg := uninitializedUnmanagedVector()

	res, err := C.decrypt(ctView, C.FheUintType(intType), &errmsg)
	if err != nil {
		return 0, errorWithMessage(err, errmsg)
	}

	return uint64(res), nil
}

func GenerateFheKeys(clientKeyPath string, serverKeyPath string, publicKeyPath string) error {
	cClientPath := C.CString(clientKeyPath)
	defer C.free(unsafe.Pointer(cClientPath))

	cServerPath := C.CString(serverKeyPath)
	defer C.free(unsafe.Pointer(cServerPath))

	cPublicPath := C.CString(publicKeyPath)
	defer C.free(unsafe.Pointer(cPublicPath))

	success := C.generate_full_keys(cClientPath, cServerPath, cPublicPath)

	if !success {
		return fmt.Errorf("failed to generate keys for fhe")
	}

	return nil
}

/**** To error module ***/

func errorWithMessage(err error, b C.UnmanagedVector) error {
	// this checks for out of gas as a special case
	if errno, ok := err.(syscall.Errno); ok && int(errno) == 2 {
		return types.Error{}
	}
	msg := copyAndDestroyUnmanagedVector(b)
	if msg == nil {
		return err
	}
	return fmt.Errorf("%s", string(msg))
}
