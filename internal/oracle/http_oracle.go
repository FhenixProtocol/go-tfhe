package oracle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/fhenixprotocol/go-tfhe/internal/api"
	"io"
	"net/http"
)

const OracleRetryAmount = 3

type HttpOracle struct{}

type requireMessage struct {
	Value     bool   `json:"value"`
	Signature string `json:"signature"`
}

var requireHttpClient http.Client = http.Client{}

func requireURL(key *string) string {
	return api.GetConfig().OracleAddress + "/require/" + *key
}

func requireKey(ciphertext []byte) string {
	// Take the Keccak256 and remove the leading 0x.
	return hex.EncodeToString(api.Keccak256(ciphertext))[2:]
}

func doHTTPRequest(method, url string, body []byte, key string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	resp, err := requireHttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (o HttpOracle) Close() {}

// PutRequire probably checks for decrypted success and not necessarily not zero?
func (HttpOracle) PutRequire(ct *api.Ciphertext, decryptedNotZero bool) error {

	key := requireKey(ct.Serialization)
	j, err := json.Marshal(requireMessage{decryptedNotZero, api.SignRequire(ct.Serialization, decryptedNotZero)})
	if err != nil {
		return err
	}
	for try := 1; try <= OracleRetryAmount+1; try++ {
		req, err := http.NewRequest(http.MethodPut, requireURL(&key), bytes.NewReader(j))
		if err != nil {
			continue
		}
		resp, err := requireHttpClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			return err
		}
		return nil
	}
	return fmt.Errorf("failed to set require")
}

func (HttpOracle) GetRequire(ct *api.Ciphertext) (bool, error) {
	ciphertext := ct.Serialization
	key := requireKey(ciphertext)
	for try := uint8(1); try <= OracleRetryAmount+1; try++ {
		req, err := http.NewRequest(http.MethodGet, requireURL(&key), http.NoBody)
		if err != nil {
			continue
		}
		resp, err := requireHttpClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || err != nil {
			continue
		}
		msg := requireMessage{}
		if err := json.Unmarshal(body, &msg); err != nil {
			// failed to validate signature
			return false, fmt.Errorf("failed to unmarshal require signature")
		}
		b := api.RequireBytesToSign(ciphertext, msg.Value)
		s, err := hex.DecodeString(msg.Signature)
		if err != nil {
			// failed to validate signature
			return false, fmt.Errorf("failed to decode hex require signature")
		}
		if !api.VerifyRequireSignature(b, s) {
			// failed to validate signature
			return false, fmt.Errorf("failed to validate require signature")
		}
		return msg.Value, nil
	}
	return false, fmt.Errorf("getRequire reached maximum retries")
}
