package fsutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
)

// EncryptDirAES encrypts all files found in the directory and subdirectories at the provided path
func EncryptDirAES(path string, key []byte) error {
	walkFn := func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// continue if entry is directory
		if e.IsDir() {
			return nil
		}

		// read file data
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		// get encrypted file data
		newData, err := encryptAES(key, data)
		if err != nil {
			return err
		}

		// write encrypted data to file
		err = os.WriteFile(path, newData, os.ModePerm)
		if err != nil {
			return err
		}

		return nil
	}

	return filepath.WalkDir(path, walkFn)
}

// DecryptDirAES decrypts all files found in the directory and subdirectories at the provided path
func DecryptDirAES(path string, key []byte) error {
	walkFn := func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// continue if entry is directory
		if e.IsDir() {
			return nil
		}

		// read file data
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		// get decrypted file data
		newData, err := decryptAES(key, data)
		if err != nil {
			return err
		}

		// write encrypted data to file
		err = os.WriteFile(path, newData, os.ModePerm)
		if err != nil {
			return err
		}

		return nil
	}

	return filepath.WalkDir(path, walkFn)
}

//
func encryptAES(key []byte, data []byte) ([]byte, error) {
	// create new cypher block
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// create gcm
	aesgcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	//
	nonce := make([]byte, aesgcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	//
	encrypted := aesgcm.Seal(nonce, nonce, data, nil)

	return encrypted, nil
}

//
func decryptAES(key []byte, data []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//
	aesgcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	//
	nonceSize := aesgcm.NonceSize()
	if len(data) < nonceSize {
		fmt.Println(err)
	}

	//
	nonce, encrypted := data[:nonceSize], data[nonceSize:]
	decrypted, err := aesgcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}
