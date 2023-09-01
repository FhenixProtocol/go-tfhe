package main

import (
	"encoding/hex"
	"fmt"
	tfhelib "github.com/fhenixprotocol/go-tfhe"
	"math/big"
	"os"
	"sync"
	"testing"
)

func InitTFHELib(sksPath, pksPath string) error {
	serverKeyFile, err := os.ReadFile(sksPath)
	if err != nil {
		return err
	}
	ok, err := tfhelib.LoadServerKey(serverKeyFile)
	if err != nil {
		return fmt.Errorf("error from tfhe: %s", err)
	}
	if !ok {
		return fmt.Errorf("load server key failed")
	}

	publicKeyFile, err := os.ReadFile(pksPath)
	if err != nil {
		return err
	}
	ok, err = tfhelib.LoadPublicKey(publicKeyFile)
	if err != nil {
		return fmt.Errorf("error from tfhe: %s", err)
	}
	if !ok {
		return fmt.Errorf("load public key failed")
	}

	return nil
}

func TestRunInternalInManyThreads(t *testing.T) {
	fmt.Println("generating keys")
	err := GenerateKeys()
	if err != nil {
		t.Fail()
	}

	err = InitTFHELib("./keys/sks", "./keys/pks")
	if err != nil {
		t.Fail()
	}

	fmt.Println("encrypting 10 and adding it to itself")
	num := big.NewInt(10)

	num1, err := tfhelib.NewCipherText(*num, 0, false)
	if err != nil {
		t.Fail()
	}

	num2, err := tfhelib.NewCipherText(*num, 0, false)
	if err != nil {
		t.Fail()
	}

	// Launch multiple goroutines, each with its own thread.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)

		// Launch a goroutine to fetch the URL.
		go func() {
			// Decrement the counter when the goroutine completes.
			defer wg.Done()

			res, err := num1.Add(num2)
			if err != nil {
				t.Fail()
			}

			fmt.Printf("Success! Got result %s...\n", hex.EncodeToString(res.Serialization)[:80])
		}()
	}

	// Wait for all goroutines to complete.
	wg.Wait()
}
