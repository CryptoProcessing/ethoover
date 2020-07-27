package main

import (
	// common
	"fmt"

	// 3rd party
	"github.com/ethereum/go-ethereum/p2p/enode"

	// internal
	"github.com/CryptoProcessing/ethoover/utils"
)

func main() {
	var node *enode.Node = utils.NewNode()
	fmt.Println(node.IP())
}
