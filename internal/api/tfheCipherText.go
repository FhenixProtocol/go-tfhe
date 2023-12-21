package api

import (
	"bytes"
	"fmt"
	"github.com/sirupsen/logrus"
	"math/big"
	"os"
	"runtime"
	"strings"
)

var logger *logrus.Logger

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

func PrintRoutineTime(name string, isEnd bool) {
	file, err := os.OpenFile("/home/user/perf/perf/perf.txt", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}

	defer file.Close()
	depth := 4
	log := ""

	for i := 0; i < depth; i++ {
		log += "\t"
	}

	banner := "++"
	if isEnd {
		banner = "--"
	}

	log += fmt.Sprintf("%s function %s at %d\n ", banner, name, "{} function {} at {}")
	_, err = file.WriteString(log)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}
}

func getFunctionName() string {
	pc, _, _, _ := runtime.Caller(1)
	funcName := runtime.FuncForPC(pc).Name()
	return funcName
}

// NewCipherText creates a new Ciphertext instance with encryption of the provided value.
func NewCipherText(value big.Int, t UintType, compact bool) (*Ciphertext, error) {
	// Perform encryption, potentially expanding the result if compact is false
	PrintRoutineTime(getFunctionName(), false)
	res, err := Encrypt(value, t)
	if err != nil {
		return nil, err
	}

	if !compact {
		res, err = ExpandCompressedValue(res, t)
		if err != nil {
			return nil, err
		}

		c := &Ciphertext{
			Serialization: res,
			UintType:      t,
			hash:          Keccak256(res),
		}

		PrintRoutineTime(getFunctionName(), true)
		return c, nil
	}

	c := &Ciphertext{
		Serialization: res,
		UintType:      t,
		hash:          Keccak256(res),
	}

	PrintRoutineTime(getFunctionName(), true)
	return c, nil
}

// NewCipherTextTrivial creates a new Ciphertext using trivial encryption - trivial encryption is used to encrypt "public" constants to
// inject into FHE operations
func NewCipherTextTrivial(value big.Int, t UintType) (*Ciphertext, error) {
	PrintRoutineTime(getFunctionName(), false)
	res, err := EncryptTrivial(value, t)
	if err != nil {
		return nil, err
	}

	c := &Ciphertext{
		Serialization: res,
		UintType:      t,
		hash:          Keccak256(res),
	}

	PrintRoutineTime(getFunctionName(), true)
	return c, nil
}

// NewCipherTextFromBytes creates a new Ciphertext from its byte representation.
func NewCipherTextFromBytes(ctBytes []byte, t UintType, compact bool) (*Ciphertext, error) {
	PrintRoutineTime(getFunctionName(), false)
	// Validate and potentially expand the ciphertext bytes
	if compact {
		res, err := ExpandCompressedValue(ctBytes, t)
		if err != nil {
			return nil, err
		}

		c := &Ciphertext{
			Serialization: res,
			UintType:      t,
			hash:          Keccak256(res),
		}

		PrintRoutineTime(getFunctionName(), true)
		return c, nil
	}

	c := &Ciphertext{
		Serialization: ctBytes,
		UintType:      t,
		hash:          Keccak256(ctBytes),
	}

	PrintRoutineTime(getFunctionName(), true)
	return c, nil
}

// NewRandomCipherText creates a random Ciphertext - only not really. It's just used for simulations and testing, so we inject some
// constant value here instead of an actual random
func NewRandomCipherText(t UintType) (*Ciphertext, error) {
	PrintRoutineTime(getFunctionName(), false)
	// Not really though!
	res, err := Encrypt(*big.NewInt(int64(5)), t)
	if err != nil {
		return nil, err
	}

	c := &Ciphertext{
		Serialization: res,
		UintType:      t,
		random:        true,
		hash:          Keccak256(res),
	}

	PrintRoutineTime(getFunctionName(), true)
	return c, nil
}

func logLevelFromString(logLevel string, defaultLevel logrus.Level) logrus.Level {
	logLevelUpper := strings.ToUpper(logLevel)
	switch logLevelUpper {
	case "ERROR":
		return logrus.ErrorLevel
	case "WARN":
		return logrus.WarnLevel
	case "INFO":
		return logrus.InfoLevel
	case "DEBUG":
		return logrus.DebugLevel
	case "TRACE":
		return logrus.TraceLevel
	default:
		return defaultLevel
	}
}

func getLogLevel(defaultLevel logrus.Level) logrus.Level {
	LogLevelEnvVarName := "LOG_LEVEL"
	logLevelEnvVar := os.Getenv(LogLevelEnvVarName)
	logLevel := logLevelFromString(logLevelEnvVar, defaultLevel)

	if logLevel > defaultLevel {
		return defaultLevel
	}

	return logLevel
}

func InitLogger(logLevel logrus.Level) {
	logger = logrus.New()
	logger.SetOutput(os.Stderr)
	logger.SetLevel(getLogLevel(logLevel))
}

// IsRandom checks if the ciphertext was randomly generated - this is used for gas simulation
func (ct *Ciphertext) IsRandom() bool {
	return ct.random
}

func (ct *Ciphertext) Cast(toType UintType) (*Ciphertext, error) {
	PrintRoutineTime(getFunctionName(), false)
	if ct.UintType == toType {
		return ct, nil
	}

	res, err := castOperation(ct.Serialization, uint8(ct.UintType), uint8(toType))
	if err != nil {
		return nil, err
	}

	c := &Ciphertext{
		Serialization: res,
		hash:          Keccak256(res),
		UintType:      ct.UintType,
	}

	PrintRoutineTime(getFunctionName(), true)
	return c, nil
}

func (ct *Ciphertext) Cmux(ifTrue *Ciphertext, ifFalse *Ciphertext) (*Ciphertext, error) {
	PrintRoutineTime(getFunctionName(), false)
	if ifFalse.UintType != ifTrue.UintType {
		return nil, fmt.Errorf("cannot use selector on uints of different types")
	}

	res, err := cmux(ct.Serialization, ifTrue.Serialization, ifFalse.Serialization, uint8(ct.UintType))
	if err != nil {
		return nil, err
	}

	c := &Ciphertext{
		Serialization: res,
		hash:          Keccak256(res),
		UintType:      ct.UintType,
	}

	PrintRoutineTime(getFunctionName(), true)
	return c, nil
}

// Decrypt decrypts the ciphertext and returns the plaintext value.
func (ct *Ciphertext) Decrypt() (*big.Int, error) {
	PrintRoutineTime(getFunctionName(), false)
	res, err := Decrypt(ct.Serialization, ct.UintType)
	PrintRoutineTime(getFunctionName(), true)
	return big.NewInt(int64(res)), err
}

func (ct *Ciphertext) performMathOperation(rhs *Ciphertext, operation uint32) (*Ciphertext, error) {
	PrintRoutineTime(fmt.Sprintf("MathOperation:%u", operation), false)
	if ct.UintType != rhs.UintType {
		return nil, fmt.Errorf("cannot perform operation on uints of different types")
	}

	res, err := mathOperation(ct.Serialization, rhs.Serialization, uint8(ct.UintType), operation)
	if err != nil {
		return nil, err
	}

	c := &Ciphertext{
		Serialization: res,
		hash:          Keccak256(res),
		UintType:      ct.UintType,
	}

	PrintRoutineTime(fmt.Sprintf("MathOperation:%u", operation), true)
	return c, nil
}

func (ct *Ciphertext) performUnaryMathOperation(operation uint32) (*Ciphertext, error) {
	PrintRoutineTime(fmt.Sprintf("UnaryMathOperation:%u", operation), false)
	res, err := unaryMathOperation(ct.Serialization, uint8(ct.UintType), operation)
	if err != nil {
		return nil, err
	}

	c := &Ciphertext{
		Serialization: res,
		hash:          Keccak256(res),
		UintType:      ct.UintType,
	}

	PrintRoutineTime(fmt.Sprintf("UnaryMathOperation:%u", operation), true)
	return c, nil
}

// Now you can use the above function to implement the original methods:

// Add performs ciphertext addition.
func (ct *Ciphertext) Add(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performMathOperation(rhs, add)
}

func (ct *Ciphertext) Sub(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performMathOperation(rhs, sub)
}

func (ct *Ciphertext) Mul(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performMathOperation(rhs, mul)
}

func (ct *Ciphertext) Lt(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performMathOperation(rhs, lt)
}

func (ct *Ciphertext) Lte(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performMathOperation(rhs, lte)
}

func (ct *Ciphertext) Div(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performMathOperation(rhs, div)
}

func (ct *Ciphertext) Gt(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performMathOperation(rhs, gt)
}

func (ct *Ciphertext) Gte(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performMathOperation(rhs, gte)
}

func (ct *Ciphertext) Rem(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performMathOperation(rhs, rem)
}

func (ct *Ciphertext) And(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performMathOperation(rhs, and)
}

func (ct *Ciphertext) Or(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performMathOperation(rhs, or)
}

func (ct *Ciphertext) Xor(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performMathOperation(rhs, xor)
}

func (ct *Ciphertext) Eq(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performMathOperation(rhs, eq)
}

func (ct *Ciphertext) Ne(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performMathOperation(rhs, ne)
}

func (ct *Ciphertext) Min(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performMathOperation(rhs, min)
}

func (ct *Ciphertext) Max(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performMathOperation(rhs, max)
}

func (ct *Ciphertext) Shl(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performMathOperation(rhs, shl)
}

func (ct *Ciphertext) Shr(rhs *Ciphertext) (*Ciphertext, error) {
	return ct.performMathOperation(rhs, shr)
}

func (ct *Ciphertext) Not() (*Ciphertext, error) {
	return ct.performUnaryMathOperation(not)
}
