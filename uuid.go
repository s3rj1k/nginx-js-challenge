package main

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// genUUID generates UUIDv4 (random).
func genUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	// this make sure that the 13th character is "4"
	b[6] = (b[6] | 0x40) & 0x4F
	// this make sure that the 17th is "8", "9", "a", or "b"
	b[8] = (b[8] | 0x80) & 0xBF

	// assemble UUIDv4
	uuid := fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])

	return strings.ToLower(uuid), nil
}
