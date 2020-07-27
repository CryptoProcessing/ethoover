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
func NewNode() *enode.Node {
	return enode.MustParse("enode://8b4b5f437edebb1ec85eabdb3fd966576ea60710b83cb1e71d698369e92837bd76f5b557736230651f10e928d9e66e39388405f3d57edfa3e4aa4a083c18210e@40.91.195.155:30303")
}
