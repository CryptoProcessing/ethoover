package utils

import (
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/crypto"
)

func NewKey() *ecdsa.PrivateKey {
	key, err := crypto.GenerateKey()
	if err != nil {
		panic("couldn't generate key: " + err.Error())
	}
	return key
}
