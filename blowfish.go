package ssoclient

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"hash/crc32"

	"github.com/go-errors/errors"
	"golang.org/x/crypto/blowfish"
)

func blowfishCreateDataPacket(data, key, iv, key2, iv2, prefix []byte) ([]byte, error) {
	prefix = append([]byte(fmt.Sprintf("%08x", crc32.ChecksumIEEE(prefix))), '\n')

	h := sha1.New()
	h.Write(data)
	hash := h.Sum(nil)
	hexHash := make([]byte, hex.EncodedLen(len(hash)))
	hex.Encode(hexHash, hash)
	prefix = append(prefix, hexHash...)
	prefix = append(prefix, '\n')

	data = append(prefix, data...)
	data = append(data, '\n')

	// create the cipher
	ecipher, err := blowfish.NewCipher(key)
	if err != nil {
		return []byte{}, errors.Wrap(err, 1)
	}

	padLen := blowfish.BlockSize - len(data)%blowfish.BlockSize
	data = append(data, make([]byte, padLen)...)

	ecbc := cipher.NewCBCEncrypter(ecipher, iv[:blowfish.BlockSize])
	ecbc.CryptBlocks(data, data)

	// abcdef -> fabcde
	data = append(data[len(data)-1:], data[:len(data)-1]...)

	ecipher, err = blowfish.NewCipher(key2)
	if err != nil {
		return []byte{}, errors.Wrap(err, 1)
	}

	ecbc = cipher.NewCBCEncrypter(ecipher, iv2[:blowfish.BlockSize])
	ecbc.CryptBlocks(data, data)

	return data, nil
}

func blowfishExtractDataPacket(data, key, iv, key2, iv2 []byte) ([]byte, error) {
	// create the cipher
	dcipher, err := blowfish.NewCipher(key2)
	if err != nil {
		return []byte{}, errors.Wrap(err, 1)
	}

	dcbc := cipher.NewCBCDecrypter(dcipher, iv2[:blowfish.BlockSize])
	dcbc.CryptBlocks(data, data)

	// fabcde -> abcdef
	data = append(data[1:], data[0])

	dcipher, err = blowfish.NewCipher(key)
	if err != nil {
		return []byte{}, errors.Wrap(err, 1)
	}

	dcbc = cipher.NewCBCDecrypter(dcipher, iv[:blowfish.BlockSize])
	dcbc.CryptBlocks(data, data)

	pos := bytes.IndexByte(data, '\n')
	if pos == -1 {
		return []byte{}, errors.Errorf("Invalid data")
	}
	data = data[pos+1:]

	pos = bytes.IndexByte(data, '\n')
	if pos == -1 {
		return []byte{}, errors.Errorf("Invalid data")
	}
	check := data[0:pos]
	data = data[pos+1:]

	pos = bytes.LastIndexByte(data, '\n')
	if pos == -1 {
		return []byte{}, errors.Errorf("Invalid data")
	}
	data = data[0:pos]

	h := sha1.New()
	h.Write(data)
	hash := h.Sum(nil)
	hexHash := make([]byte, hex.EncodedLen(len(hash)))
	hex.Encode(hexHash, hash)

	if !bytes.Equal(check, hexHash) {
		return []byte{}, errors.Errorf("Data hash mismatch")
	}

	return data, nil
}
