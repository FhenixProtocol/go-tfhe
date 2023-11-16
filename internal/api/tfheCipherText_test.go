package api_test

import (
	"github.com/fhenixprotocol/go-tfhe/internal/api"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestNewCipherText(t *testing.T) {
	err := setupKeysForTests()

	value := big.NewInt(12345)
	ct, err := api.NewCipherText(*value, api.Uint32, false)
	if err != nil {
		t.Fatalf("Error creating new ciphertext: %v", err)
	}
	if ct.UintType != api.Uint32 {
		t.Errorf("Expected UintType1, got %v", ct.UintType)
	}

	res, err := ct.Decrypt()
	if err != nil {
		t.Fatalf("Failed to decrypt: %s", err)
	}

	if res.Uint64() != value.Uint64() {
		t.Fatalf("Expected: %d != %d", res.Uint64(), value.Uint64())
	}
}

func TestCiphertextCastOperations(t *testing.T) {
	err := setupKeysForTests()
	if err != nil {
		t.Fatalf("Failed to load keys: %s", err)
	}

	val := big.NewInt(10)

	testCases := []struct {
		name     string
		fromType api.UintType
		toType   api.UintType
	}{

		{"CastUint8ToUint8", api.Uint8, api.Uint8},
		{"CastUint8ToUint16", api.Uint8, api.Uint16},
		{"CastUint8ToUint32", api.Uint8, api.Uint32},
		{"CastUint16ToUint8", api.Uint16, api.Uint8},
		{"CastUint16ToUint16", api.Uint16, api.Uint16},
		{"CastUint16ToUint32", api.Uint16, api.Uint32},
		{"CastUint32ToUint8", api.Uint32, api.Uint8},
		{"CastUint32ToUint16", api.Uint32, api.Uint16},
		{"CastUint32ToUint32", api.Uint32, api.Uint32},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ct, _ := api.NewCipherText(*val, tt.fromType, false)
			res, err := ct.Cast(tt.toType)
			if err != nil {
				t.Fatalf("Got error %v", err)
			}
			if res == nil {
				t.Fatalf("Expected a result, got nil")
			}

			gotHash := res.Hash()
			expectedHash := api.Keccak256(res.Serialization)
			if gotHash != api.Hash(expectedHash) {
				t.Fatalf("Mismatch in ciphertext hash")
			}

			resDec, err := res.Decrypt()
			if err != nil {
				t.Fatalf("Error while decrypting %+v", err)
			}

			assert.Equal(t, resDec, val)

		})
	}

}

func TestCipherTextOperations(t *testing.T) {
	err := setupKeysForTests()
	if err != nil {
		t.Fatalf("Failed to load keys: %s", err)
	}

	type operationFunc func(a, b *api.Ciphertext) (*api.Ciphertext, error)

	addOp := func(a, b *api.Ciphertext) (*api.Ciphertext, error) {
		return a.Add(b)
	}
	addResultFunc := func(a, b *big.Int) *big.Int { return new(big.Int).Add(a, b) }
	addResultFuncOverflow := func(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Add(a, b), big.NewInt(256)) }

	subOp := func(a, b *api.Ciphertext) (*api.Ciphertext, error) {
		return a.Sub(b)
	}
	subResultFunc := func(a, b *big.Int) *big.Int { return new(big.Int).Sub(a, b) }
	mulOp := func(a, b *api.Ciphertext) (*api.Ciphertext, error) {
		return a.Mul(b)
	}
	mulResultFunc := func(a, b *big.Int) *big.Int { return new(big.Int).Mul(a, b) }

	lteOp := func(a, b *api.Ciphertext) (*api.Ciphertext, error) {
		return a.Lte(b)
	}
	lteResultFunc := func(a, b *big.Int) *big.Int {
		if a.Cmp(b) <= 0 {
			return big.NewInt(1)
		}
		return big.NewInt(0)
	}

	ltOp := func(a, b *api.Ciphertext) (*api.Ciphertext, error) {
		return a.Lt(b)
	}
	ltResultFunc := func(a, b *big.Int) *big.Int {
		if a.Cmp(b) < 0 {
			return big.NewInt(1)
		}
		return big.NewInt(0)
	}

	//// Assuming div function returns a Ciphertext of the quotient.
	//divOp := func(a, b *api.Ciphertext) (*api.Ciphertext, error) {
	//	return a.Div(b) // Assuming there's a Div method on Ciphertext.
	//}
	//divResultFunc := func(a, b *big.Int) *big.Int { return new(big.Int).Div(a, b) }

	testCases := []struct {
		name     string
		value1   *big.Int
		value2   *big.Int
		uintType api.UintType
		op       operationFunc
		resultFn func(a, b *big.Int) *big.Int
		err      error
	}{

		{"AddUint8", big.NewInt(10), big.NewInt(20), api.Uint16, addOp,
			addResultFunc, nil},
		{"AddUint16", big.NewInt(10), big.NewInt(20), api.Uint16, addOp,
			addResultFunc, nil},
		{"AddUin32", big.NewInt(10), big.NewInt(20), api.Uint32, addOp,
			addResultFunc, nil},
		{"AddLarge", big.NewInt(123_000_000), big.NewInt(456_000_000), api.Uint32, addOp,
			addResultFunc, nil},
		{"AddOverflow", big.NewInt(255), big.NewInt(1), api.Uint8, addOp,
			addResultFuncOverflow, nil},
		{"SubUint8", big.NewInt(20), big.NewInt(10), api.Uint8, subOp,
			subResultFunc, nil},
		{"SubUint16", big.NewInt(20), big.NewInt(10), api.Uint16, subOp, subResultFunc, nil},
		{"SubUint32", big.NewInt(123_000_000), big.NewInt(456_000), api.Uint32, subOp, subResultFunc, nil},
		// Multiplication tests
		{"MulUint8", big.NewInt(10), big.NewInt(20), api.Uint8, mulOp, mulResultFunc, nil},
		{"MulUint16", big.NewInt(10), big.NewInt(20), api.Uint16, mulOp, mulResultFunc, nil},
		{"MulLarge", big.NewInt(1_000_000), big.NewInt(2_000), api.Uint32, mulOp, mulResultFunc, nil},
		// Less Than tests
		{"LtUint8", big.NewInt(10), big.NewInt(20), api.Uint8, ltOp, ltResultFunc, nil},
		{"LtUint16", big.NewInt(1_000), big.NewInt(500), api.Uint16, ltOp, ltResultFunc, nil},
		{"LtUint32", big.NewInt(1_000_000), big.NewInt(500_000), api.Uint32, ltOp, ltResultFunc, nil},
		// Less Than or Equal tests
		{"LteUint8", big.NewInt(10), big.NewInt(10), api.Uint8, lteOp, lteResultFunc, nil},
		{"LteUint16", big.NewInt(500), big.NewInt(500), api.Uint16, lteOp, lteResultFunc, nil},
		{"LteUint32", big.NewInt(500_000), big.NewInt(500_000), api.Uint32, lteOp, lteResultFunc, nil},

		// Division tests (assuming Div function exists on Ciphertext)
		//{"DivUint8", big.NewInt(100), big.NewInt(20), api.Uint8, divOp, divResultFunc, nil},
		//{"DivUint16", big.NewInt(1_000), big.NewInt(2), api.Uint16, divOp, divResultFunc, nil},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ct1, _ := api.NewCipherText(*tt.value1, tt.uintType, false)
			ct2, _ := api.NewCipherText(*tt.value2, tt.uintType, false)

			result, err := tt.op(ct1, ct2)
			if err != tt.err {
				t.Fatalf("Expected error %v, got %v", tt.err, err)
			}
			if err == nil && result == nil {
				t.Fatalf("Expected a result, got nil")
			}

			gotHash := result.Hash()
			expectedHash := api.Keccak256(result.Serialization)
			if gotHash != api.Hash(expectedHash) {
				t.Fatalf("Mismatch in ciphertext hash")
			}

			resDec, err := result.Decrypt()
			if err != nil {
				t.Fatalf("Expected an error when adding decrypting")
			}

			expected := tt.resultFn(tt.value1, tt.value2)
			if resDec.Cmp(expected) != 0 {
				t.Fatalf("Result is not what we expected: %s vs %s", resDec, expected)
			}

		})
	}
}
