package api_test

import (
	"github.com/fhenixprotocol/go-tfhe/internal/api"
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

	divOp := func(a, b *api.Ciphertext) (*api.Ciphertext, error) {
		return a.Div(b)
	}
	divResultFunc := func(a, b *big.Int) *big.Int { return new(big.Int).Div(a, b) }

	gtOp := func(a, b *api.Ciphertext) (*api.Ciphertext, error) {
		return a.Gt(b)
	}
	gtResultFunc := func(a, b *big.Int) *big.Int {
		if a.Cmp(b) > 0 {
			return big.NewInt(1)
		}
		return big.NewInt(0)
	}

	gteOp := func(a, b *api.Ciphertext) (*api.Ciphertext, error) {
		return a.Gte(b)
	}
	gteResultFunc := func(a, b *big.Int) *big.Int {
		if a.Cmp(b) >= 0 {
			return big.NewInt(1)
		}
		return big.NewInt(0)
	}

	remOp := func(a, b *api.Ciphertext) (*api.Ciphertext, error) {
		return a.Rem(b)
	}
	remResultFunc := func(a, b *big.Int) *big.Int { return new(big.Int).Rem(a, b) }

	andOp := func(a, b *api.Ciphertext) (*api.Ciphertext, error) {
		return a.And(b)
	}
	andResultFunc := func(a, b *big.Int) *big.Int { return new(big.Int).And(a, b) }

	orOp := func(a, b *api.Ciphertext) (*api.Ciphertext, error) {
		return a.Or(b)
	}
	orResultFunc := func(a, b *big.Int) *big.Int { return new(big.Int).Or(a, b) }

	xorOp := func(a, b *api.Ciphertext) (*api.Ciphertext, error) {
		return a.Xor(b)
	}
	xorResultFunc := func(a, b *big.Int) *big.Int { return new(big.Int).Xor(a, b) }

	eqOp := func(a, b *api.Ciphertext) (*api.Ciphertext, error) {
		return a.Eq(b)
	}
	eqResultFunc := func(a, b *big.Int) *big.Int {
		if a.Cmp(b) == 0 {
			return big.NewInt(1)
		}
		return big.NewInt(0)
	}

	neOp := func(a, b *api.Ciphertext) (*api.Ciphertext, error) {
		return a.Ne(b)
	}
	neResultFunc := func(a, b *big.Int) *big.Int {
		if a.Cmp(b) != 0 {
			return big.NewInt(1)
		}
		return big.NewInt(0)
	}

	minOp := func(a, b *api.Ciphertext) (*api.Ciphertext, error) {
		return a.Min(b)
	}
	minResultFunc := func(a, b *big.Int) *big.Int {
		if a.Cmp(b) <= 0 {
			return a
		}
		return b
	}

	maxOp := func(a, b *api.Ciphertext) (*api.Ciphertext, error) {
		return a.Max(b)
	}
	maxResultFunc := func(a, b *big.Int) *big.Int {
		if a.Cmp(b) >= 0 {
			return a
		}
		return b
	}

	shlOp := func(a, b *api.Ciphertext) (*api.Ciphertext, error) {
		return a.Shl(b)
	}
	shlResultFunc := func(a, b *big.Int) *big.Int { return a.Lsh(a, uint(b.Uint64())) }

	shrOp := func(a, b *api.Ciphertext) (*api.Ciphertext, error) {
		return a.Shr(b)
	}
	shrResultFunc := func(a, b *big.Int) *big.Int { return a.Rsh(a, uint(b.Uint64())) }

	// todo add more ops

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
		// Division tests
		{"DivUint8", big.NewInt(100), big.NewInt(20), api.Uint8, divOp, divResultFunc, nil},
		{"DivUint16", big.NewInt(1_000), big.NewInt(2), api.Uint16, divOp, divResultFunc, nil},
		{"DivUint32", big.NewInt(1_000_024), big.NewInt(500_012), api.Uint32, divOp, divResultFunc, nil},
		// Greater Than tests
		{"GtUint8-true", big.NewInt(10), big.NewInt(20), api.Uint8, gtOp, gtResultFunc, nil},
		{"GtUint8-false", big.NewInt(10), big.NewInt(10), api.Uint8, gtOp, gtResultFunc, nil},
		{"GtUint16-true", big.NewInt(1_000), big.NewInt(500), api.Uint16, gtOp, gtResultFunc, nil},
		{"GtUint16-false", big.NewInt(1_000), big.NewInt(1000), api.Uint16, gtOp, gtResultFunc, nil},
		{"GtUint32-true", big.NewInt(1_000_000), big.NewInt(999_999), api.Uint32, gtOp, gtResultFunc, nil},
		{"GtUint32-false", big.NewInt(1_000_000), big.NewInt(1_000_001), api.Uint32, gtOp, gtResultFunc, nil},
		// Greater Than or Equal tests
		{"GteUint8-true", big.NewInt(10), big.NewInt(10), api.Uint8, gteOp, gteResultFunc, nil},
		{"GteUint8-false", big.NewInt(10), big.NewInt(9), api.Uint8, gteOp, gteResultFunc, nil},
		{"GteUint16-true", big.NewInt(1_000), big.NewInt(100), api.Uint16, gteOp, gteResultFunc, nil},
		{"GteUint16-false", big.NewInt(1_000), big.NewInt(999), api.Uint16, gteOp, gteResultFunc, nil},
		{"GteUint32-true", big.NewInt(1_000_000), big.NewInt(1_000_000), api.Uint32, gteOp, gteResultFunc, nil},
		{"GteUint32-false", big.NewInt(1_000_000), big.NewInt(1_000_001), api.Uint32, gteOp, gteResultFunc, nil},
		// Remainder tests
		{"RemUint8", big.NewInt(102), big.NewInt(20), api.Uint8, remOp, remResultFunc, nil},
		{"RemUint16", big.NewInt(1_000), big.NewInt(2), api.Uint16, remOp, remResultFunc, nil},
		{"RemUint32", big.NewInt(1_000_024), big.NewInt(500_025), api.Uint32, remOp, remResultFunc, nil},
		// Bitwise And tests
		{"AndUint8", big.NewInt(102), big.NewInt(20), api.Uint8, andOp, andResultFunc, nil},
		{"AndUint16", big.NewInt(1_000), big.NewInt(2), api.Uint16, andOp, andResultFunc, nil},
		{"AndUint32", big.NewInt(1_000_024), big.NewInt(500_025), api.Uint32, andOp, andResultFunc, nil},
		// Bitwise Or tests
		{"OrUint8", big.NewInt(102), big.NewInt(20), api.Uint8, orOp, orResultFunc, nil},
		{"OrUint16", big.NewInt(1_000), big.NewInt(2), api.Uint16, orOp, orResultFunc, nil},
		{"OrUint32", big.NewInt(1_000_024), big.NewInt(500_025), api.Uint32, orOp, orResultFunc, nil},
		// Bitwise Xor tests
		{"XorUint8", big.NewInt(102), big.NewInt(20), api.Uint8, xorOp, xorResultFunc, nil},
		{"XorUint16", big.NewInt(1_000), big.NewInt(2), api.Uint16, xorOp, xorResultFunc, nil},
		{"XorUint32", big.NewInt(1_000_024), big.NewInt(500_025), api.Uint32, xorOp, xorResultFunc, nil},
		// Equality tests
		{"EqUint8-true", big.NewInt(10), big.NewInt(10), api.Uint8, eqOp, eqResultFunc, nil},
		{"EqUint8-false", big.NewInt(10), big.NewInt(11), api.Uint8, eqOp, eqResultFunc, nil},
		{"EqUint16-true", big.NewInt(1_000), big.NewInt(1_000), api.Uint16, eqOp, eqResultFunc, nil},
		{"EqUint16-false", big.NewInt(1_000), big.NewInt(999), api.Uint16, eqOp, eqResultFunc, nil},
		{"EqUint32-true", big.NewInt(1_000_000), big.NewInt(1_000_000), api.Uint32, eqOp, eqResultFunc, nil},
		{"EqUint32-false", big.NewInt(1_000_000), big.NewInt(1_000_001), api.Uint32, eqOp, eqResultFunc, nil},
		// Inequality tests
		{"NeUint8-true", big.NewInt(10), big.NewInt(10), api.Uint8, neOp, neResultFunc, nil},
		{"NeUint8-false", big.NewInt(10), big.NewInt(11), api.Uint8, neOp, neResultFunc, nil},
		{"NeUint16-true", big.NewInt(1_000), big.NewInt(1_000), api.Uint16, neOp, neResultFunc, nil},
		{"NeUint16-false", big.NewInt(1_000), big.NewInt(999), api.Uint16, neOp, neResultFunc, nil},
		{"NeUint32-true", big.NewInt(1_000_000), big.NewInt(1_000_000), api.Uint32, neOp, neResultFunc, nil},
		{"NeUint32-false", big.NewInt(1_000_000), big.NewInt(1_000_001), api.Uint32, neOp, neResultFunc, nil},
		// Minimum tests
		{"MinUint8-lhs", big.NewInt(10), big.NewInt(11), api.Uint8, minOp, minResultFunc, nil},
		{"MinUint8-rhs", big.NewInt(10), big.NewInt(9), api.Uint8, minOp, minResultFunc, nil},
		{"MinUint16-lhs", big.NewInt(1_000), big.NewInt(2_000), api.Uint16, minOp, minResultFunc, nil},
		{"MinUint16-rhs", big.NewInt(1_000), big.NewInt(999), api.Uint16, minOp, minResultFunc, nil},
		{"MinUint32-lhs", big.NewInt(1_000_000), big.NewInt(2_000_000), api.Uint32, minOp, minResultFunc, nil},
		{"MinUint32-rhs", big.NewInt(1_000_000), big.NewInt(900_999), api.Uint32, minOp, minResultFunc, nil},
		// Maximum tests
		{"MaxUint8-lhs", big.NewInt(11), big.NewInt(10), api.Uint8, maxOp, maxResultFunc, nil},
		{"MaxUint8-rhs", big.NewInt(10), big.NewInt(11), api.Uint8, maxOp, maxResultFunc, nil},
		{"MaxUint16-lhs", big.NewInt(2_000), big.NewInt(1_000), api.Uint16, maxOp, maxResultFunc, nil},
		{"MaxUint16-rhs", big.NewInt(1_000), big.NewInt(999), api.Uint16, maxOp, maxResultFunc, nil},
		{"MaxUint32-lhs", big.NewInt(2_000_000), big.NewInt(1_000_000), api.Uint32, maxOp, maxResultFunc, nil},
		{"MaxUint32-rhs", big.NewInt(1_000_000), big.NewInt(900_001), api.Uint32, maxOp, maxResultFunc, nil},
		// Shift left tests
		{"ShlUint8", big.NewInt(102), big.NewInt(1), api.Uint8, shlOp, shlResultFunc, nil},
		{"ShlUint16", big.NewInt(1_000), big.NewInt(2), api.Uint16, shlOp, shlResultFunc, nil},
		{"ShlUint32", big.NewInt(1_000_024), big.NewInt(5), api.Uint32, shlOp, shlResultFunc, nil},
		// Shift right tests
		{"ShrUint8", big.NewInt(102), big.NewInt(1), api.Uint8, shrOp, shrResultFunc, nil},
		{"ShrUint16", big.NewInt(1_000), big.NewInt(2), api.Uint16, shrOp, shrResultFunc, nil},
		{"ShrUint32", big.NewInt(1_000_024), big.NewInt(5), api.Uint32, shrOp, shrResultFunc, nil},
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
