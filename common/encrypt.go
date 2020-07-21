package common

import "github.com/ldsec/lattigo/bfv"

func EncryptIntCiphertext(encryptor bfv.Encryptor, value int) *bfv.Ciphertext {
	params := GetParams()
	encoder := bfv.NewEncoder(params)
	valueIntArray := make([]int64, 1<<params.LogN)
	valueIntArray[0] = int64(value)
	plaintext := bfv.NewPlaintext(params)
	encoder.EncodeInt(valueIntArray, plaintext)
	ciphertext := encryptor.EncryptNew(plaintext)
	return ciphertext
}

func EncryptInt(encryptor bfv.Encryptor, value int) []byte {
	params := GetParams()
	encoder := bfv.NewEncoder(params)
	valueIntArray := make([]int64, 1<<params.LogN)
	valueIntArray[0] = int64(value)
	plaintext := bfv.NewPlaintext(params)
	encoder.EncodeInt(valueIntArray, plaintext)
	ciphertext := encryptor.EncryptNew(plaintext)
	ciphertextBytes, _ := ciphertext.MarshalBinary()
	return ciphertextBytes
}

func DecryptInt(decryptor bfv.Decryptor, value []byte) int {
	params := GetParams()
	encoder := bfv.NewEncoder(params)
	ciphertext := bfv.Ciphertext{}
	ciphertext.UnmarshalBinary(value)
	plaintext := decryptor.DecryptNew(&ciphertext)
	res := encoder.DecodeInt(plaintext)
	return int(res[0])
}
