package ssoclient

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestBlowfishEncryptDecryptSimple(t *testing.T) {
	key, _ := hex.DecodeString("96d95c25ac2cb22783577f9863b81ad171be81a871e43aa1500b898674d477eb6edd5e77b62b7a81705b4c8fe8ab2f1152a39fb8c145fc3a")
	iv, _ := hex.DecodeString("1ca9e6dc87b38be7")
	key2, _ := hex.DecodeString("a4540e9630745ecdf0199e7dc64ed9c10e7bbfe1946e493c2f2a693779536aa629ce01d387689f0e1fe66e25e89138d77bae65cb56fb605a")
	iv2, _ := hex.DecodeString("ab03cffc5fb9ceed")
	data := []byte("This is a test,\n1234")
	t.Logf("Wanted  : %s", string(data))

	prefix := make([]byte, 64)
	_, err := rand.Read(prefix)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	// make sure prefix has a newline, to check for an earlier bug
	prefix[6] = '\n'

	packet, err := blowfishCreateDataPacket(data, key, iv, key2, iv2, prefix)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	obtained, err := blowfishExtractDataPacket(packet, key, iv, key2, iv2)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	if !bytes.Equal(data, obtained) {
		t.FailNow()
	}
	t.Logf("Obtained: %s", string(obtained))
}
