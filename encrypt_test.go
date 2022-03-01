package fsutil

import (
	"fmt"
	"testing"
)

func TestAES(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	data := []byte("data to encrypt")

	encrypted, err := encryptAES(key, data)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("encrypted", string(encrypted))

	decrypted, err := decryptAES(key, encrypted)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("decrypted", string(decrypted))

	if string(decrypted) != string(data) {
		t.Error("decrypted cypher should be same as input data")
		return
	}
}

func TestEncryptDirAES(t *testing.T) {
	err := EncryptDirAES("./_target_test", []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Error(err)
		return
	}
}

func TestDecryptDirAES(t *testing.T) {
	err := DecryptDirAES("./_target_test", []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Error(err)
		return
	}
}
