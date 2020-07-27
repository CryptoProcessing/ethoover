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
	var node *enode.Node = utils.NewNode(utils.UintID(0x00), "127.0.0.1:30303")
	fmt.Println(node.IP())
}
