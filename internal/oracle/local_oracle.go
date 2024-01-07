package oracle

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fhenixprotocol/go-tfhe/internal/api"
	"github.com/fhenixprotocol/go-tfhe/internal/oracle/memorydb"
	"golang.org/x/crypto/nacl/box"
	"math/big"
	"os"
	"strconv"
)

type MemoryDb struct {
	db *memorydb.Database
}

func NewLocalDbStorage(_ string) (*MemoryDb, error) {
	db := memorydb.New()
	return &MemoryDb{db: db}, nil
}

func (o MemoryDb) Close() {
	_ = o.db.Close()
}

func (o MemoryDb) Decrypt(ct *api.Ciphertext) (string, error) {
	result, err := ct.Decrypt()
	if err != nil {
		return "", err
	}
	resultAsString := strconv.Itoa(int(result.Int64()))

	err = o.CacheDecryptResult(ct, resultAsString)
	if err != nil {
		return "", err
	}

	return resultAsString, nil
}

func classicalPublicKeyEncrypt(value *big.Int, userPublicKey []byte) ([]byte, error) {
	encrypted, err := box.SealAnonymous(nil, value.Bytes(), (*[32]byte)(userPublicKey), rand.Reader)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func encryptToUserKey(value *big.Int, pubKey []byte) ([]byte, error) {
	ct, err := classicalPublicKeyEncrypt(value, pubKey)
	if err != nil {
		return nil, err
	}

	// TODO: for testing
	err = os.WriteFile("/tmp/public_encrypt_result", ct, 0o644)
	if err != nil {
		return nil, err
	}

	return ct, nil
}

// todo (eshel) document and implement
// todo (eshel) return value should be bytes or ct?
func (o MemoryDb) Reencrypt(ct *api.Ciphertext, pubKey []byte) (string, error) {
	result, err := ct.Decrypt()
	if err != nil {
		return "", err
	}

	// todo (eshel) encrypt again
	reencrypted, err := encryptToUserKey(result, pubKey)

	// todo (eshel) should we cache something here?
	reencryptedAsString := hex.EncodeToString(reencrypted)

	return reencryptedAsString, nil
}

func (o MemoryDb) PutRequire(ct *api.Ciphertext, decryptedNotZero bool) error {
	key := requireKey(ct.Serialization)
	j, err := json.Marshal(dbRequireMessage{decryptedNotZero})
	if err != nil {
		return err
	}
	return o.db.Put([]byte(key), j)
}

func (o MemoryDb) GetRequire(ct *api.Ciphertext) (bool, error) {
	ciphertext := ct.Serialization
	key := requireKey(ciphertext)

	data, err := o.db.Get([]byte(key))
	if err != nil {
		if errors.Is(err, memorydb.ErrMemorydbNotFound) {
			// Key does not exist
			return false, nil
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

func (o *MemoryDb) CacheDecryptResult(ct *api.Ciphertext, decResult string) error {
	key := decryptKey(ct.Serialization)
	j, err := json.Marshal(dbDecryptMessage{decResult})
	if err != nil {
		return err
	}
	return o.db.Put([]byte(key), j)
}
