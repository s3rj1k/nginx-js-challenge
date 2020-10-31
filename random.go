package main

import (
	"math/rand"
	"strconv"
)

// genNewNonce generates new cryptographic nonce
func genNewNonce() string {
	mu.Lock()
	number := strconv.Itoa(rand.Intn(maxNonce))
	mu.Unlock()

	return number
}
