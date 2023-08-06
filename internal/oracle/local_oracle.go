package oracle

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fhenixprotocol/go-tfhe/internal/api"
	"github.com/syndtr/goleveldb/leveldb"
)

type LevelDBOracle struct {
	db *leveldb.DB
}

type levelDbRequireMessage struct {
	Value bool `json:"value"`
}

func (o LevelDBOracle) requireKey(ciphertext []byte) string {
	// Take the Keccak256 and remove the leading 0x.
	return hex.EncodeToString(api.Keccak256(ciphertext))[2:]
}

func NewLevelDBOracle(dbPath string) (*LevelDBOracle, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &LevelDBOracle{db: db}, nil
}

func (o LevelDBOracle) Close() {
	o.db.Close()
}

func (o LevelDBOracle) PutRequire(ct *api.Ciphertext, decryptedNotZero bool) error {
	key := o.requireKey(ct.Serialization)
	j, err := json.Marshal(levelDbRequireMessage{decryptedNotZero})
	if err != nil {
		return err
	}
	return o.db.Put([]byte(key), j, nil)
}

func (o LevelDBOracle) GetRequire(ct *api.Ciphertext) (bool, error) {
	ciphertext := ct.Serialization
	key := o.requireKey(ciphertext)

	data, err := o.db.Get([]byte(key), nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			// Key does not exist
			return false, nil
		}
		// Some other error occurred
		return false, err
	}

	msg := levelDbRequireMessage{}
	if err := json.Unmarshal(data, &msg); err != nil {
		// failed to validate signature
		return false, fmt.Errorf("failed to unmarshal require signature")
	}
	return msg.Value, nil
}
