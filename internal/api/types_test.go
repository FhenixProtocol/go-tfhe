package api_test

import (
	"bytes"
	"encoding/hex"
	"github.com/fhenixprotocol/go-tfhe/internal/api"
	"testing"
)

func TestKeccak256(t *testing.T) {
	// Known hashes can be taken from a trusted Keccak256 implementation
	// For the sake of this example, let's pretend the hash of "hello" is "somehashvalue" (this is NOT the real hash)
	knownHashes := []struct {
		input  []byte
		output string
	}{
		{[]byte("test"), "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658"},
		{[]byte{}, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
		{[]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "936c50c4900ca03bab8ae3b05daf7c6e4d83eb7e588997b8edd4ab8e7b7757dd"},
	}

	for _, tt := range knownHashes {
		t.Run(string(tt.input), func(t *testing.T) {
			result := api.Keccak256(tt.input)
			expectedBytes, err := hex.DecodeString(tt.output)
			if err != nil {
				t.Errorf("Expected result is not valid hex: %s", err)
				t.Fail()
			}
			if !bytes.Equal(result, expectedBytes) {
				t.Errorf("got %x, want %x", result, tt.output)
			}
		})
	}

	// Testing the hash size
	t.Run("HashSize", func(t *testing.T) {
		result := api.Keccak256([]byte("test"))
		if len(result) != 32 {
			t.Errorf("Keccak256 hash size is not 32 bytes, got: %d bytes", len(result))
		}
	})

	// You might want to add more edge cases, such as input of varying sizes or other specific cases relevant to your application.
}
