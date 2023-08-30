package api_test

import (
	"github.com/fhenixprotocol/go-tfhe/internal/api/amd64"
	"os"
	"path"
)

func setupKeysForTests() error {
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

	amd64.SKS, err = os.ReadFile(sksPath)
	if err != nil {
		return err
	}
	amd64.CKS, err = os.ReadFile(cksPath)
	if err != nil {
		return err
	}
	amd64.PKS, err = os.ReadFile(pksPath)
	if err != nil {
		return err
	}

	_, err = amd64.DeserializePublicKey(amd64.PKS)
	if err != nil {
		return err
	}
	_, err = amd64.DeserializeServerKey(amd64.SKS)
	if err != nil {
		return err
	}
	_, err = amd64.DeserializeClientKey(amd64.CKS)
	if err != nil {
		return err
	}

	return nil
}
