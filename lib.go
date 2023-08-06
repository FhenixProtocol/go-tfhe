//go:build cgo

package tfhe

import (
	"crypto/ed25519"
	"fmt"
	"github.com/fhenixprotocol/go-tfhe/internal/api"
	"github.com/fhenixprotocol/go-tfhe/internal/oracle"
	"os"
	"path/filepath"
)

// Represents a TFHE ciphertext.
//
// Once a ciphertext has a value (either from deserialization, encryption or makeRandom()),
// it must not be set another value. If that is needed, a new ciphertext must be created.
// todo (Itzik): Testing whether or not passing the serialized data and not the raw pointer.
// Obviously it will come at a performance cost, but possibly the security/clarity of the code during the
// early days could be worth it? For the part seems serialization of FHEu8 is about 20us

// Represents a TFHE ciphertext.
//
// Once a ciphertext has a value (either from deserialization, encryption or makeRandom()),
// it must not be set another value. If that is needed, a new ciphertext must be created.

func LoadClientKey(clientKeyBytes []byte) (bool, error) {
	return api.DeserializeClientKey(clientKeyBytes)
}

func LoadPublicKey(publicKeyBytes []byte) (bool, error) {
	return api.DeserializePublicKey(publicKeyBytes)
}

func LoadServerKey(serverKeyBytes []byte) (bool, error) {
	return api.DeserializeServerKey(serverKeyBytes)
}

func Decrypt(ciphertext Ciphertext) (uint64, error) {

	if api.LoadKeysDone {
		return 0, fmt.Errorf("cannot decrypt if keys are not initialized")
	}

	result, err := api.Decrypt(ciphertext.Serialization, ciphertext.UintType)
	if err != nil {
		return 0, err
	}

	return result, nil
}

func PublicKey() ([]byte, error) {
	return api.GetPublicKey()
}

func CheckRequire(ciphertext *Ciphertext) (bool, error) {
	result, err := oracleStorage.GetRequire(ciphertext)
	if err != nil {
		return false, err
	}

	return result, nil
}

func StoreRequire(ciphertext *Ciphertext, plaintext uint64) (bool, error) {
	notZero := plaintext != 0
	err := oracleStorage.PutRequire(ciphertext, notZero)

	return notZero, err
}

func NewRandomCipherText(t UintType) (*Ciphertext, error) {

	//config := api.GetConfig()
	//if config == nil {
	//	return nil, fmt.Errorf("cannot generate ciphertext without config")
	//}
	//
	//publicKeyPath := config.PublicKeyPath
	//if config.HomeDir != nil {
	//	publicKeyPath = filepath.Join(*config.HomeDir, config.PublicKeyPath)
	//}
	//
	//publicKey, err := os.ReadFile(publicKeyPath)
	//if err != nil {
	//	return nil, err
	//}
	//
	//_, err = LoadPublicKey(publicKey)
	//if err != nil {
	//	return nil, err
	//}
	//
	//println("Done setting public key as ", publicKeyPath)

	return api.NewRandomCipherText(t)
}

func InitTfhe(config *Config) error {
	if config == nil {
		return fmt.Errorf("config cannot be empty")
	}
	if api.LoadKeysDone {
		return nil
	}

	api.SetConfig(*config)

	clientKeyPath := config.ClientKeyPath
	serverKeyPath := config.ServerKeyPath
	publicKeyPath := config.PublicKeyPath

	oraclePrivatePath := config.OraclePrivateKeyPath
	oraclePublicPath := config.OraclePublicKeyPath
	oracleDbPath := config.OracleDbPath

	if config.HomeDir != nil {
		clientKeyPath = filepath.Join(*config.HomeDir, config.ClientKeyPath)
		serverKeyPath = filepath.Join(*config.HomeDir, config.ServerKeyPath)
		publicKeyPath = filepath.Join(*config.HomeDir, config.PublicKeyPath)

		oraclePrivatePath = filepath.Join(*config.HomeDir, config.OraclePrivateKeyPath)
		oraclePublicPath = filepath.Join(*config.HomeDir, config.OraclePublicKeyPath)

		oracleDbPath = filepath.Join(*config.HomeDir, config.OracleDbPath)
	}

	serverKey, err := os.ReadFile(serverKeyPath)
	if err != nil {
		return err
	}

	clientKey, err := os.ReadFile(clientKeyPath)
	if err != nil {
		return err
	}

	publicKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return err
	}

	_, err = LoadServerKey(serverKey)
	if err != nil {
		return err
	}

	_, err = LoadClientKey(clientKey)
	if err != nil {
		return err
	}

	_, err = LoadPublicKey(publicKey)
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

	} else {
		db, err := oracle.NewLevelDBOracle(oracleDbPath)
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

	if err := os.MkdirAll(clientDir, 0755); err != nil {
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

	if err := os.WriteFile(fullPublicKeyPath, public, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(fullPrivateKeyPath, private, 0600); err != nil {
		return err
	}
	return nil
}

//func SignRequire(ciphertext []byte, value bool) string {
//	return api.SignRequire(ciphertext, value)
//}
//
//func RequireBytesToSign(ciphertext []byte, value bool) []byte {
//	return api.RequireBytesToSign(ciphertext, value)
//}
//
//func VerifyRequireSignature(message []byte, signature []byte) bool {
//	return api.VerifyRequireSignature(message, signature)
//}

func Version() (string, error) {
	version, err := api.LibTfheVersion()

	return version, err
}
