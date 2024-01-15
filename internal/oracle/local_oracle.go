package oracle

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fhenixprotocol/go-tfhe/internal/api"
	"github.com/fhenixprotocol/go-tfhe/internal/oracle/memorydb"
	"golang.org/x/crypto/nacl/box"
	"math/big"
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

type EthEncryptedReturn struct {
	Version        string `json:"version"`
	Nonce          string `json:"nonce"`
	EphemPublicKey string `json:"ephemPublicKey"`
	Ciphertext     string `json:"ciphertext"`
}

func encryptForUser(value *big.Int, userPublicKey []byte) ([]byte, error) {
	ephemeralPub, ephemeralPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 24)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	encrypted := box.Seal(nil, value.Bytes(), (*[24]byte)(nonce), (*[32]byte)(userPublicKey), ephemeralPriv)
	////encrypted, err := box.SealAnonymous(nil, value.Bytes(), (*[32]byte)(userPublicKey), rand.Reader)
	//if err != nil {
	//	return nil, err
	//}

	encryptedReturnValue := EthEncryptedReturn{
		Version:        "x25519-xsalsa20-poly1305",
		Nonce:          base64.StdEncoding.EncodeToString(nonce),
		EphemPublicKey: base64.StdEncoding.EncodeToString(ephemeralPub[:]),
		Ciphertext:     base64.StdEncoding.EncodeToString(encrypted),
	}

	return json.Marshal(&encryptedReturnValue)
}

func encryptToUserKey(value *big.Int, pubKey []byte) ([]byte, error) {
	ct, err := encryptForUser(value, pubKey)
	if err != nil {
		return nil, err
	}

	return ct, nil
}

func (o MemoryDb) SealOutput(ct *api.Ciphertext, pubKey []byte) (string, error) {
	result, err := ct.Decrypt()
	if err != nil {
		return "", err
	}

	sealedResult, err := encryptToUserKey(result, pubKey)

	// todo (eshel) should we cache something here?
	sealedAsString := hex.EncodeToString(sealedResult)

	return sealedAsString, nil
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
