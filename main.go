package main

import (
			"net"
			"fmt"
			"strings"
			"strconv"
			"encoding/binary"

			"github.com/ethereum/go-ethereum/p2p"
			"github.com/ethereum/go-ethereum/p2p/enr"
			"github.com/ethereum/go-ethereum/p2p/enode"

			"github.com/CryptoProcessing/ethoover/utils"
)

func main() {
	var node *enode.Node = newNode(uintID(0x00), "127.0.0.1:30303")
	fmt.Println(node)
	fmt.Println(p2p.NewPeer)
}
