package api_test

import (
	"github.com/fhenixprotocol/go-tfhe/internal/api"
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

	err = api.GenerateFheKeys(cksPath, sksPath, pksPath)
	if err != nil {
		return err
	}

	api.SKS, err = os.ReadFile(sksPath)
	if err != nil {
		return err
	}
	api.CKS, err = os.ReadFile(cksPath)
	if err != nil {
		return err
	}
	api.PKS, err = os.ReadFile(pksPath)
	if err != nil {
		return err
	}

	_, err = api.DeserializePublicKey(api.PKS)
	if err != nil {
		return err
	}
	_, err = api.DeserializeServerKey(api.SKS)
	if err != nil {
		return err
	}
	_, err = api.DeserializeClientKey(api.CKS)
	if err != nil {
		return err
	}

	return nil
}
