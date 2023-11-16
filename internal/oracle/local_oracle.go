package oracle

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fhenixprotocol/go-tfhe/internal/api"
	"github.com/fhenixprotocol/go-tfhe/internal/oracle/memorydb"
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
