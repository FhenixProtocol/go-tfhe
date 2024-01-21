## What's Going on Here?

The base layer for all the FHE needs that an FHE-based chain will need, assuming they're written in Go.

## What does this repo contain

### Libtfhe-wrapper

Is a Rust wrapper around tfhe.rs - making it easier to work with and giving us more control in how to 
construct interfaces. Also other stuff, like managing keys, setting configs, etc.
We implement a FFI with Golang that allows Go code to call the Rust functions. In addition, we also support WASM targets
though this requires our modified version of tfhe-rs found at https://github.com/fhenixprotocol/tfhe-rs in order to support the wasm32-unknown-unknown target.

Building to WASM is done using `make wasm-rust`, which currently uses the file `bind-to-wasm.rs` in the examples folder

### Go-Tfhe

The main library that is used from the outside. Go code that wants to use TFHE stuff simply includes this library and then uses
functions that are exposed from lib.go. Encrypted ciphertexts are handled using the "CipherText" type, which is kind of an unfriendly interface right now and should
be improved in the future.

Note that in the amd_64 target (and any non-wasm) Go will automatically pull and link the .so file from internal/api, so you may have 
to recompile it again depending on your underlying operating system

Also supports building statically using muslc if anyone cares

#### Usage

`cmd/main.go` is basically a debug CLI that shows some basic functionality and allows you to play around with it.
You can build it using `make build-go`. I recently improved the interface, so a `-h` should be all you need to figure it out

#### API List

##### Lib.go

- `LoadClientKey([]byte) (bool, error)`: Loads a client key
- `LoadPublicKey([]byte) (bool, error)`: Loads a public key
- `LoadServerKey([]byte) (bool, error)`: Loads a server key
- `Decrypt(Ciphertext) (uint64, error)`: Decrypts a ciphertext
- `SealOutput(Ciphertext, []byte)`: Seals the decrypted value of a ciphertext to a specific user's public key
- `PublicKey() ([]byte, error)`: Retrieves the public key
- `CheckRequire(*Ciphertext) (bool, error)`: Checks a requirement via the oracle
- `StoreRequire(*Ciphertext, uint64) (bool, error)`: Stores a requirement into the oracle
- `NewRandomCipherText(UintType) (*Ciphertext, error)`: Creates a new random ciphertext
- `InitTfhe(*Config) error`: Initializes the TFHE library
- `CloseTfhe()`: Closes the TFHE library and performs cleanup
- `GenerateFheKeys(string, string, string, string) error`: Generates FHE keys
- `GenerateRequireKeys(string, string, string) error`: Generates keys required for the oracle
- `Version() uint32`: Retrieves the library version

##### CipherText

Ciphertext API List
- `NewCipherText(big.Int, UintType, bool) (*Ciphertext, error)`: Creates a new Ciphertext by encrypting a given value.

- `NewCipherTextTrivial(big.Int, UintType) (*Ciphertext, error)`: Creates a new Ciphertext using trivial encryption.

- `NewCipherTextFromBytes([]byte, UintType, bool) (*Ciphertext, error)`: Creates a new Ciphertext from its byte representation.

- `NewRandomCipherText(UintType) (*Ciphertext, error)`: Creates a new random Ciphertext.

- `Hash() Hash`: Calculates and returns the hash of the serialized ciphertext.

- `IsRandom() bool`: Checks if the ciphertext was randomly generated.

- `Add(*Ciphertext) (*Ciphertext, error)`: Performs ciphertext addition.

- `Decrypt() (*big.Int, error)`: Decrypts the ciphertext and returns the plaintext value.

- `Sub(*Ciphertext) (*Ciphertext, error)`: Performs ciphertext subtraction.

- `Mul(*Ciphertext) (*Ciphertext, error)`: Performs ciphertext multiplication.

- `Lt(*Ciphertext) (*Ciphertext, error)`: Performs less than comparison between ciphertexts.

- `Lte(*Ciphertext) (*Ciphertext, error)`: Performs less than or equal comparison between ciphertexts.

- `Div(*Ciphertext) (*Ciphertext, error)`: Performs ciphertext division.

- `Gt(*Ciphertext) (*Ciphertext, error)`: Performs greater than comparison between ciphertexts.

- `Gte(*Ciphertext) (*Ciphertext, error)`: Performs greater than or equal comparison between ciphertexts.

- `And(*Ciphertext) (*Ciphertext, error)`: Performs ciphertext bitwise And operation.

- `Or(*Ciphertext) (*Ciphertext, error)`: Performs ciphertext bitwise Or operation.

- `Xor(*Ciphertext) (*Ciphertext, error)`: Performs ciphertext bitwise Xor operation.

- `Eq(*Ciphertext) (*Ciphertext, error)`: Performs equality comparison between ciphertexts.

- `Ne(*Ciphertext) (*Ciphertext, error)`: Performs inequality comparison between ciphertexts.

- `Min(*Ciphertext) (*Ciphertext, error)`: Returns the smaller of the two ciphertexts.

- `Max(*Ciphertext) (*Ciphertext, error)`: Returns the bigger of the two ciphertexts.

- `Shl(*Ciphertext) (*Ciphertext, error)`: Performs bitwise Shift-left operation.

- `Shr(*Ciphertext) (*Ciphertext, error)`: Performs bitwise Shift-right operation.

- `Not() (*Ciphertext, error)`: Performs bitwise Not operation.

#### Encryption & Decryption

```go
// Initialize
if err := InitTfhe(&config); err != nil {
	log.Fatal("Failed to initialize TFHE:", err)
}
defer CloseTfhe()

value := big.NewInt(123)
cipherText, err := NewCipherText(*value, Uint8, false)
if err != nil {
    log.Fatal("Error creating cipher text:", err)
}

// Decrypting a ciphertext
result, err := Decrypt(cipherText)
if err != nil {
    log.Fatal("Failed to decrypt:", err)
}
```

#### Mathematical Operations

```go
result, err := cipherText1.Mul(cipherText2)
if err != nil {
    log.Fatal("Error multiplying cipher texts:", err)
}
```