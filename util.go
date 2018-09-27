package nxusercheck

import (
	"crypto/rand"
	"encoding/hex"
)

func randomPass(sz int) string {
	if sz <= 0 {
		sz = 16
	}
	b := make([]byte, sz)
	n, err := rand.Read(b)
	if err != nil || n != len(b) {
		panic("Can't read from crypto/rand")
	}
	return hex.EncodeToString(b)
}
