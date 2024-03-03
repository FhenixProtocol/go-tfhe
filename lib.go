package tfhe

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/fhenixprotocol/go-tfhe/internal/api"
	"github.com/fhenixprotocol/go-tfhe/internal/oracle"
)

// LoadClientKey loads the client key - client key is essentially the "super master key" and is used to decrypt data
// and perform require checks and such
func LoadClientKey(clientKeyBytes []byte) (bool, error) {
	return api.DeserializeClientKey(clientKeyBytes)
}

// LoadPublicKey loads the public key - public key is used by the client (or the library if exposed to the user)
// to encrypt a plaintext
func LoadPublicKey(publicKeyBytes []byte) (bool, error) {
	return api.DeserializePublicKey(publicKeyBytes)
}

// LoadServerKey loads the server key - server key is the key used to perform mathematical operations on ciphertexts.
// It is replicated for all nodes in the network
func LoadServerKey(serverKeyBytes []byte) (bool, error) {
	return api.DeserializeServerKey(serverKeyBytes)
}

// Decrypt decrypts the given Ciphertext.
// It checks if the keys are initialized before performing decryption
func Decrypt(ciphertext Ciphertext) (uint64, error) {
	if len(ciphertext.Serialization) == 0 {
		return 0, fmt.Errorf("cannot decrypt without encrypted bytes")
	}

	result, err := oracleStorage.Decrypt(&ciphertext)
	if err != nil {
		return 0, err
	}

	resultAsNumber, err := strconv.Atoi(result)
	if err != nil {
		return 0, nil
	}

	return uint64(resultAsNumber), nil
	//if api.LoadKeysDone {
	//	return 0, fmt.Errorf("cannot decrypt if keys are not initialized")
	//}
	//
	//result, err := api.Decrypt(ciphertext.Serialization, ciphertext.UintType)
	//if err != nil {
	//	return 0, err
	//}
	//
	//return result, nil
}

// SealOutput encrypts the given Ciphertext to the given public key.
// It checks if the keys are initialized before performing decryption
func SealOutput(ciphertext Ciphertext, pubKey []byte) ([]byte, error) {
	if len(ciphertext.Serialization) == 0 {
		return nil, fmt.Errorf("cannot check require without encrypted bytes")
	}

	result, err := oracleStorage.SealOutput(&ciphertext, pubKey)
	if err != nil {
		return nil, err
	}

	return hex.DecodeString(result)
}

// PublicKey retrieves the current public key
func PublicKey() ([]byte, error) {
	return api.GetPublicKey()
}

// CheckRequire consults the oracle to check a certain requirement based on the ciphertext
func CheckRequire(ciphertext *Ciphertext) (bool, error) {
	if ciphertext == nil {
		return false, fmt.Errorf("cannot check require on nil")
	}
	if len(ciphertext.Serialization) == 0 {
		return false, fmt.Errorf("cannot check require without encrypted bytes")
	}

	if oracleStorage == nil {
		return false, fmt.Errorf("Cannot check require if database is not initialized")
	}

	result, err := oracleStorage.GetRequire(ciphertext)
	if err != nil {
		return false, err
	}

	return result, nil
}

func Require(ct *Ciphertext) bool {
	config := api.GetConfig()
	if config.OracleType == "local" {
		return putRequire(ct)
	} else if config.OracleType == "network" {
		return getRequire(ct)
	} else {
		panic("Unknown oracle type: " + config.OracleType)
	}
}

// Puts the given ciphertext as a require to the oracle DB or exits the process on errors.
// Returns the require value.
func putRequire(ct *Ciphertext) bool {
	plaintext, err := Decrypt(*ct)
	if err != nil {
		panic(err)
	}

	result, err := StoreRequire(ct, plaintext)
	if err != nil {
		panic("Failed to decrypt value")
	}

	return result
}

// Gets the given require from the oracle DB and returns its value.
// Exits the process on errors or signature verification failure.
func getRequire(ct *Ciphertext) bool {
	result, err := CheckRequire(ct)
	if err != nil {
		return false
	}

	return result
}

// StoreRequire stores a requirement into the oracle - this is used by the EVM to manage ciphertexts
func StoreRequire(ciphertext *Ciphertext, plaintext uint64) (bool, error) {
	notZero := plaintext != 0
	err := oracleStorage.PutRequire(ciphertext, notZero)

	return notZero, err
}

// NewRandomCipherText generates a new random ciphertext based on the UintType provided.
func NewRandomCipherText(t UintType) (*Ciphertext, error) {
	return api.NewRandomCipherText(t)
}

// InitTfhe initializes TFHE with the given configuration.
func InitTfhe(config *Config) error {
	var err error

	if config == nil {
		return fmt.Errorf("config cannot be empty")
	}
	if api.LoadKeysDone {
		_, err = LoadServerKey(api.SKS)
		if err != nil {
			return err
		}

		_, err = LoadClientKey(api.CKS)
		if err != nil {
			return err
		}

		_, err = LoadPublicKey(api.PKS)
		if err != nil {
			return err
		}

		return nil
	}

	api.SetConfig(*config)

	clientKeyPath := filepath.Join(config.HomeDir, config.ClientKeyPath)
	serverKeyPath := filepath.Join(config.HomeDir, config.ServerKeyPath)
	publicKeyPath := filepath.Join(config.HomeDir, config.PublicKeyPath)

	oraclePrivatePath := filepath.Join(config.HomeDir, config.OraclePrivateKeyPath)
	oraclePublicPath := filepath.Join(config.HomeDir, config.OraclePublicKeyPath)

	oracleDbPath := filepath.Join(config.HomeDir, config.OracleDbPath)

	api.SKS, err = os.ReadFile(serverKeyPath)
	if err != nil {
		return err
	}

	api.CKS, err = os.ReadFile(clientKeyPath)
	if err != nil {
		return err
	}

	api.PKS, err = os.ReadFile(publicKeyPath)
	if err != nil {
		return err
	}

	_, err = LoadServerKey(api.SKS)
	if err != nil {
		return err
	}

	_, err = LoadClientKey(api.CKS)
	if err != nil {
		return err
	}

	_, err = LoadPublicKey(api.PKS)
	if err != nil {
		return err
	}

	if config.OracleType == "http" {
		if config.IsOracle {
			api.KeyRequirePrivate, err = os.ReadFile(oraclePrivatePath)
			if err != nil {
				return err
			}
		}
		api.KeyRequirePublic, err = os.ReadFile(oraclePublicPath)
		if err != nil {
			return err
		}

		oracleStorage = oracle.HttpOracle{}
	} else if config.OracleType == "network" {
		oracleStorage = oracle.NewDecryptionOracleClient()
	} else {
		db, err := oracle.NewLocalDbStorage(oracleDbPath)
		if err != nil {
			return err
		}

		oracleStorage = db
	}

	api.LoadKeysDone = true

	return nil
}

func CloseTfhe() {
	if oracleStorage != nil {
		oracleStorage.Close()
	}
}

// GenerateFheKeys is a CLI command only or testing command
func GenerateFheKeys(homeDir string, serverKeyPath string, clientKeyPath string, publicKeyPath string) error {
	fullClientKeyPath := filepath.Join(homeDir, clientKeyPath)
	fullServerKeyPath := filepath.Join(homeDir, serverKeyPath)
	fullPublicKeyPath := filepath.Join(homeDir, publicKeyPath)

	err := createDirectoryIfNotExist(fullClientKeyPath)
	if err != nil {
		return err
	}

	// Make directories for private key if they don't exist
	err = createDirectoryIfNotExist(fullServerKeyPath)
	if err != nil {
		return err
	}

	// Make directories for private key if they don't exist
	err = createDirectoryIfNotExist(fullPublicKeyPath)
	if err != nil {
		return err
	}

	return api.GenerateFheKeys(fullClientKeyPath, fullServerKeyPath, fullPublicKeyPath)
}

func createDirectoryIfNotExist(fullClientKeyPath string) error {
	// Make directories for private key if they don't exist
	clientDir := filepath.Dir(fullClientKeyPath)

	if err := os.MkdirAll(clientDir, 0o755); err != nil {
		return err
	}
	return nil
}

// GenerateRequireKeys is a CLI command only or testing command
func GenerateRequireKeys(homeDir string, privateKeyPath string, publicKeyPath string) error {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}

	fullPrivateKeyPath := filepath.Join(homeDir, privateKeyPath)
	fullPublicKeyPath := filepath.Join(homeDir, publicKeyPath)

	// Make directories for private key if they don't exist
	err = createDirectoryIfNotExist(fullPrivateKeyPath)
	if err != nil {
		return err
	}

	// Make directories for public key if they don't exist
	err = createDirectoryIfNotExist(fullPublicKeyPath)
	if err != nil {
		return err
	}

	if err := os.WriteFile(fullPublicKeyPath, public, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(fullPrivateKeyPath, private, 0o600); err != nil {
		return err
	}
	return nil
}

func Version() string {
	return api.LibTfheVersion()
}
