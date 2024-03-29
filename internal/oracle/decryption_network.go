//go:build amd64 || arm64

package oracle

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	pb "github.com/fhenixprotocol/decryption-oracle-proto/go/oracle"
	"github.com/fhenixprotocol/go-tfhe/internal/api"
	"github.com/fhenixprotocol/go-tfhe/internal/oracle/memorydb"
)

type DecryptionOracle struct {
	client *DecryptionNetworkClient
	// local cache for decrypted numbers & require statement results
	db *memorydb.Database
}

const DefaultDecryptionOracle = "0.0.0.0:50051"

func NewDecryptionOracleClient() *DecryptionOracle {
	oracle := DecryptionOracle{
		client: nil,
		db:     nil,
	}

	if oracle.db == nil {
		db := memorydb.New()
		oracle.db = db
	}

	if oracle.client == nil {
		config := api.GetConfig()
		address := config.OracleAddress
		if address == "" {
			address = DefaultDecryptionOracle
		}
		newClient := NewDecryptionNetworkClient(address)

		oracle.client = &newClient
	}

	return &oracle
}

func (oracle DecryptionOracle) Decrypt(ct *api.Ciphertext) (string, error) {
	ciphertext := ct.Serialization
	key := decryptKey(ciphertext)

	data, err := oracle.db.Get([]byte(key))
	if err != nil {
		if errors.Is(err, memorydb.ErrMemorydbNotFound) {
			// Key does not exist in local db; try checking via decryption network
			decrypted, signature, err := (*oracle.client).Decrypt(&pb.FheEncrypted{
				Data: ct.Serialization,
				Type: pb.EncryptedType(ct.UintType),
			})
			if err != nil {
				return "", fmt.Errorf("could not decrypt: %v", err)
			}

			fmt.Printf("Decrypted: %v\n", decrypted)
			fmt.Printf("Signature: %s\n", signature)

			// todo: verify signature

			// store result in local cache before returning
			return decrypted, oracle.CacheDecryptResult(ct, decrypted)
		}

		// Some other error occurred
		return "", err
	}

	msg := dbDecryptMessage{}
	if err := json.Unmarshal(data, &msg); err != nil {
		// failed to validate signature
		return "", fmt.Errorf("failed to unmarshal require signature")
	}
	return msg.Value, nil
}

func (oracle DecryptionOracle) SealOutput(ct *api.Ciphertext, pubKey []byte) (string, error) {
	// todo: maybe cache something here
	// todo: NOTE that this is how we should call the decryption network, but it doesn't work yet over there
	reencrypted, signature, err := (*oracle.client).Reencrypt(
		&pb.FheEncrypted{
			Data: ct.Serialization,
			Type: pb.EncryptedType(ct.UintType),
		},
		hex.EncodeToString(pubKey),
	)
	if err != nil {
		return "", fmt.Errorf("could not reencrypt: %v", err)
	}

	fmt.Printf("Reencrypted: %v\n", reencrypted)
	fmt.Printf("Signature: %s\n", signature)

	// todo: verify signature

	return reencrypted, nil
}

func (oracle DecryptionOracle) GetRequire(ct *api.Ciphertext) (bool, error) {
	ciphertext := ct.Serialization
	key := requireKey(ciphertext)

	data, err := oracle.db.Get([]byte(key))
	if err != nil {
		if errors.Is(err, memorydb.ErrMemorydbNotFound) {
			// Key does not exist in local db; try checking via decryption network
			decrypted, signature, err := (*oracle.client).AssertIsNil(&pb.FheEncrypted{
				Data: ct.Serialization,
				Type: pb.EncryptedType(ct.UintType),
			})
			if err != nil {
				return false, fmt.Errorf("could not decrypt: %v", err)
			}

			fmt.Printf("Decrypted: %v\n", decrypted)
			fmt.Printf("Signature: %s\n", signature)

			// todo: verify signature

			// store result in local cache before returning
			return decrypted, oracle.PutRequire(ct, decrypted)
		}
		// Some other error occurred
		return false, err
	}

	msg := dbRequireMessage{}
	if err := json.Unmarshal(data, &msg); err != nil {
		// failed to validate signature
		return false, fmt.Errorf("failed to unmarshal require signature")
	}
	return msg.Value, nil
}

func (oracle DecryptionOracle) PutRequire(ct *api.Ciphertext, decryptedNotZero bool) error {
	key := requireKey(ct.Serialization)
	j, err := json.Marshal(dbRequireMessage{decryptedNotZero})
	if err != nil {
		return err
	}
	return oracle.db.Put([]byte(key), j)
}

func (oracle DecryptionOracle) CacheDecryptResult(ct *api.Ciphertext, decResult string) error {
	key := decryptKey(ct.Serialization)
	j, err := json.Marshal(dbDecryptMessage{decResult})
	if err != nil {
		return err
	}
	return oracle.db.Put([]byte(key), j)
}

func (oracle DecryptionOracle) Close() {
	(*oracle.client).Close()
}
