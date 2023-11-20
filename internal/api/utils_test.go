package api_test

import (
	"github.com/fhenixprotocol/go-tfhe/internal/api/amd64"
	"os"
	"path"
)

func setupKeysForTests() error {

	pk, err := amd64.GetPublicKey()
	if pk != nil && err == nil {
		return nil
	}

	tmpDir, err := os.MkdirTemp("", "myPrefix")
	if err != nil {
		return err
	}

	cksPath := path.Join(tmpDir, "cks")
	pksPath := path.Join(tmpDir, "pks")
	sksPath := path.Join(tmpDir, "sks")

	err = amd64.GenerateFheKeys(cksPath, sksPath, pksPath)
	if err != nil {
		return err
	}

	SKS, err := os.ReadFile(sksPath)
	if err != nil {
		return err
	}
	CKS, err := os.ReadFile(cksPath)
	if err != nil {
		return err
	}
	PKS, err := os.ReadFile(pksPath)
	if err != nil {
		return err
	}

	_, err = amd64.DeserializePublicKey(PKS)
	if err != nil {
		return err
	}
	_, err = amd64.DeserializeServerKey(SKS)
	if err != nil {
		return err
	}
	_, err = amd64.DeserializeClientKey(CKS)
	if err != nil {
		return err
	}

	return nil
}
