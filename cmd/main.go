package main

import (
	"encoding/hex"
	"fmt"
	tfhelib "github.com/fhenixprotocol/go-tfhe"
	"github.com/spf13/cobra"
	"math/big"
	"os"
)

func main() {

	var rootCmd = &cobra.Command{Use: "myApp"}

	var cmdKeygen = &cobra.Command{
		Use:   "keygen",
		Short: "Generate keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			return GenerateKeys()
		},
	}

	var cmdVersion = &cobra.Command{
		Use:   "version",
		Short: "Display version",
		RunE: func(cmd *cobra.Command, args []string) error {
			return Version()
		},
	}

	var pksPath string
	var cmdEncrypt = &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt data",
		RunE: func(cmd *cobra.Command, args []string) error {
			return Encrypt(pksPath)
		},
	}
	cmdEncrypt.Flags().StringVarP(&pksPath, "pks", "p", "./keys/pks", "Path to public key store")

	var sksPath string
	var cmdDeserializeSKS = &cobra.Command{
		Use:   "deserialize-sks",
		Short: "Deserialize secret key store",
		RunE: func(cmd *cobra.Command, args []string) error {
			return Deserialize(sksPath)
		},
	}
	cmdDeserializeSKS.Flags().StringVarP(&sksPath, "sks", "s", "./keys/sks", "Path to secret key store")

	var cmdAdd = &cobra.Command{
		Use:   "add",
		Short: "Add two example numbers and return the result",
		RunE: func(cmd *cobra.Command, args []string) error {
			return Add(sksPath, pksPath)
		},
	}
	cmdAdd.Flags().StringVarP(&sksPath, "sks", "s", "./keys/sks", "Path to server key")
	cmdAdd.Flags().StringVarP(&pksPath, "pks", "p", "./keys/pks", "Path to public key")

	rootCmd.AddCommand(cmdKeygen, cmdVersion, cmdEncrypt, cmdDeserializeSKS, cmdAdd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func Version() error {
	libtfheVersion, err := tfhelib.Version()
	if err != nil {
		return err
	}
	fmt.Printf("Tfhe-rs version: %s\n", libtfheVersion)
	return nil
}

func Encrypt(path string) error {
	clientKeyFile, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	ok, err := tfhelib.LoadPublicKey(clientKeyFile)
	if err != nil {
		return fmt.Errorf("error from tfhe: %s", err)
	}
	if !ok {
		return fmt.Errorf("load key failed")
	}

	fmt.Printf("Load public key success\n")

	// num := big.NewInt(1000)

	res, err := tfhelib.NewRandomCipherText(2)
	if err != nil {
		return fmt.Errorf("error from tfhe NewCipherText: %s", err)
	}
	bytes := res.Serialization

	fmt.Printf("Got ciphertext: %s", hex.EncodeToString(bytes))
	return nil
}

func Deserialize(path string) error {
	serverKeyFile, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	ok, err := tfhelib.LoadServerKey(serverKeyFile)
	if err != nil {
		return fmt.Errorf("error from tfhe: %s", err)
	}

	fmt.Printf("Tfhe-rs result: %t\n", ok)
	return nil
}

func Add(skPath string, pksPath string) error {
	serverKeyFile, err := os.ReadFile(skPath)
	if err != nil {
		return err
	}

	ok, err := tfhelib.LoadServerKey(serverKeyFile)
	if err != nil {
		return fmt.Errorf("error from tfhe: %s", err)
	}
	if !ok {
		return fmt.Errorf("load key failed")
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
		return fmt.Errorf("load key failed")
	}

	num := big.NewInt(10)

	num1, err := tfhelib.NewCipherText(*num, 0, false)
	if err != nil {
		return fmt.Errorf("error from tfhe NewCipherText: %s", err)
	}
	num2, err := tfhelib.NewCipherText(*num, 0, false)
	if err != nil {
		return fmt.Errorf("error from tfhe NewCipherText: %s", err)
	}

	res, err := num1.Add(num2)
	if err != nil {
		return fmt.Errorf("error while adding: %s", err)
	}

	fmt.Printf("Success! Got result %s", hex.EncodeToString(res.Serialization))
	return nil
}

func GenerateKeys() error {
	err :=
		tfhelib.GenerateFheKeys("./keys/", "./sks", "./cks", "./pks")
	if err != nil {
		return fmt.Errorf("error from tfhe GenerateFheKeys: %s", err)
	}
	return nil
}
