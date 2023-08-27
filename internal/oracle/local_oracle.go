package oracle

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fhenixprotocol/go-tfhe/internal/api"
	"github.com/fhenixprotocol/go-tfhe/internal/oracle/memorydb"
)

type MemoryDb struct {
	db *memorydb.Database
}

type dbRequireMessage struct {
	Value bool `json:"value"`
}

func (o MemoryDb) requireKey(ciphertext []byte) string {
	// Take the Keccak256 and remove the leading 0x.
	return hex.EncodeToString(api.Keccak256(ciphertext))[2:]
}

func NewLevelDBOracle(_ string) (*MemoryDb, error) {
	db := memorydb.New()
	return &MemoryDb{db: db}, nil
}

func (o MemoryDb) Close() {
	_ = o.db.Close()
}

func (o MemoryDb) PutRequire(ct *api.Ciphertext, decryptedNotZero bool) error {
	key := o.requireKey(ct.Serialization)
	j, err := json.Marshal(dbRequireMessage{decryptedNotZero})
	if err != nil {
		return err
	}
	return o.db.Put([]byte(key), j)
}

func (o MemoryDb) GetRequire(ct *api.Ciphertext) (bool, error) {
	ciphertext := ct.Serialization
	key := o.requireKey(ciphertext)

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
