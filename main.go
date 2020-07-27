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
	var node *enode.Node = utils.NewNode("enode://8b4b5f437edebb1ec85eabdb3fd966576ea60710b83cb1e71d698369e92837bd76f5b557736230651f10e928d9e66e39388405f3d57edfa3e4aa4a083c18210e@127.0.0.1:30303")
	fmt.Println(node.IP())
}
