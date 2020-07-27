package utils

import (
	// common
	// "net"
	// "fmt"
	// "strings"
	// "strconv"
	"encoding/binary"

	// 3rd party
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// uintID encodes i into a node ID.
func UintID(i uint16) enode.ID {
	var id enode.ID
	binary.BigEndian.PutUint16(id[:], i)
	return id
}

// returns new node
func NewNode(uri string) *enode.Node {
	return enode.MustParse(uri)
}
