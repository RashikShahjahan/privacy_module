package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

// Predefined key length
const keySize = 2048

func main() {
	privateKey, publicKey, _ := GenerateRSAKeys()
	data := []byte("Hello, World!")
	encryptedData, _ := EncryptData(data, publicKey)
	decryptedData, _ := DecryptData(encryptedData, privateKey)
	signature, _ := GenerateSignature(data, privateKey)
	_ = VerifySignature(data, signature, publicKey)

	fmt.Println("Original data: ", string(data))
	fmt.Println("Decrypted data: ", string(decryptedData))
}

// GenerateRSAKeys generates and returns RSA public and private keys of a predefined key length
func GenerateRSAKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, err
	}
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey, nil
}

// EncryptData encrypts the given data using the provided public key and RSA algorithm
func EncryptData(data []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, data, nil)
}

// DecryptData decrypts data using the provided private key and RSA algorithm
func DecryptData(ciphertext []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
}

// GenerateSignature generates a digital signature for the data using the private key
func GenerateSignature(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hashed := sha256.Sum256(data)
	return rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed[:], nil)
}

// VerifySignature verifies the digital signature of data using the public key
func VerifySignature(data []byte, signature []byte, publicKey *rsa.PublicKey) error {
	hashed := sha256.Sum256(data)
	return rsa.VerifyPSS(publicKey, crypto.SHA256, hashed[:], signature, nil)
}
