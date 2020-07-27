package utils

import (
			// common
			"net"
			"fmt"
			"strings"
			"strconv"
			"encoding/binary"

			// 3rd party
			"github.com/ethereum/go-ethereum/p2p/enr"
			"github.com/ethereum/go-ethereum/p2p/enode"
)

// uintID encodes i into a node ID.
func UintID(i uint16) enode.ID {
	var id enode.ID
	binary.BigEndian.PutUint16(id[:], i)
	return id
}

// returns new node
func NewNode(id enode.ID, addr string) *enode.Node {
	var r enr.Record
	if addr != "" {
		// Set the port if present.
		if strings.Contains(addr, ":") {
			hs, ps, err := net.SplitHostPort(addr)
			if err != nil {
				panic(fmt.Errorf("invalid address %q", addr))
			}
			port, err := strconv.Atoi(ps)
			if err != nil {
				panic(fmt.Errorf("invalid port in %q", addr))
			}
			r.Set(enr.TCP(port))
			r.Set(enr.UDP(port))
			addr = hs
		}
		// Set the IP.
		ip := net.ParseIP(addr)
		if ip == nil {
			panic(fmt.Errorf("invalid IP %q", addr))
		}
		r.Set(enr.IP(ip))
	}
	return enode.SignNull(&r, id)
}
