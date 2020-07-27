package main

import (
	"errors"
	"github.com/CryptoProcessing/ethoover/utils"
	"github.com/ethereum/go-ethereum/crypto"
	ethlog "github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"log"
	"net"
	"time"
)

var MainnetBootnodes = []string{
	// Ethereum Foundation Go Bootnodes
	"enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303",   // bootnode-aws-ap-southeast-1-001
	"enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303",     // bootnode-aws-us-east-1-001
	"enode://ca6de62fce278f96aea6ec5a2daadb877e51651247cb96ee310a318def462913b653963c155a0ef6c7d50048bba6e6cea881130857413d9f50a621546b590758@34.255.23.113:30303",   // bootnode-aws-eu-west-1-001
	"enode://279944d8dcd428dffaa7436f25ca0ca43ae19e7bcf94a8fb7d1641651f92d121e972ac2e8f381414b80cc8e5555811c2ec6e1a99bb009b3f53c4c69923e11bd8@35.158.244.151:30303",  // bootnode-aws-eu-central-1-001
	"enode://8499da03c47d637b20eee24eec3c356c9a2e6148d6fe25ca195c7949ab8ec2c03e3556126b0d7ed644675e78c4318b08691b7b57de10e5f0d40d05b09238fa0a@52.187.207.27:30303",   // bootnode-azure-australiaeast-001
	"enode://103858bdb88756c71f15e9b5e09b56dc1be52f0a5021d46301dbbfb7e130029cc9d0d6f73f693bc29b665770fff7da4d34f3c6379fe12721b5d7a0bcb5ca1fc1@191.234.162.198:30303", // bootnode-azure-brazilsouth-001
	"enode://715171f50508aba88aecd1250af392a45a330af91d7b90701c436b618c86aaa1589c9184561907bebbb56439b8f8787bc01f49a7c77276c58c1b09822d75e8e8@52.231.165.108:30303",  // bootnode-azure-koreasouth-001
	"enode://5d6d7cd20d6da4bb83a1d28cadb5d409b64edf314c0335df658c1a54e32c7c4a7ab7823d57c39b6a757556e68ff1df17c748b698544a55cb488b52479a92b60f@104.42.217.25:30303",   // bootnode-azure-westus-001
}

type sharedUDPConn struct {
	*net.UDPConn
	unhandled chan discover.ReadPacket
}

// ReadFromUDP implements discv5.conn
func (s *sharedUDPConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	packet, ok := <-s.unhandled
	if !ok {
		return 0, nil, errors.New("connection was closed")
	}
	l := len(packet.Data)
	if l > len(b) {
		l = len(b)
	}
	copy(b[:l], packet.Data[:l])
	return l, packet.Addr, nil
}

// Close implements discv5.conn
func (s *sharedUDPConn) Close() error {
	return nil
}

func main() {
	//var node *enode.Node = utils.NewNode("enode://8b4b5f437edebb1ec85eabdb3fd966576ea60710b83cb1e71d698369e92837bd76f5b557736230651f10e928d9e66e39388405f3d57edfa3e4aa4a083c18210e@127.0.0.1:30303")
	//log.Println(node.IP(), node.String(), node.Pubkey(), node.Record())
	var r enr.Record
	r.Set(enr.IP{0, 0, 0, 0})
	addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		log.Fatalln(err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalln(err)
	}
	realaddr := conn.LocalAddr().(*net.UDPAddr)

	key, _ := crypto.GenerateKey()
	db, _ := enode.OpenDB("")

	localNode := enode.NewLocalNode(db, key)

	localNode.SetFallbackUDP(realaddr.Port)

	unhandled := make(chan discover.ReadPacket, 100)

	var sconn *sharedUDPConn = &sharedUDPConn{
		conn,
		unhandled,
	}

	//targetNode := utils.NewNode("enode://006e0037a83ee46b93968f9c6c4a4208ea88c9c5c043c9a5775d42c8e17bb21730db26aa01e0d098db758bcb9f0a3c3c9c6a221dc8e06a4fcd14dc3123d90a9f@73.240.200.107:55818")

	log.Println(localNode.Node().IP(), localNode.Node().Pubkey())

	var bootNodes []*enode.Node

	for _, bn := range MainnetBootnodes {
		bootNodes = append(bootNodes, utils.NewNode(bn))
	}

	config := discover.Config{
		PrivateKey: key,
		Log:        ethlog.New("newNode", "localhost"),
		Bootnodes:  bootNodes,
	}

	udp, err := discover.ListenV4(sconn, localNode, config)
	log.Println(err, udp)

	//error := udp.Ping( targetNode )
	//log.Println(error)

	targetAddr, _ := net.ResolveUDPAddr("udp", "149.81.164.114:30303")
	localNode.UDPContact(targetAddr)
	//randomNodes := udp.RandomNodes()

	for i := 0; i < 200; i++ {
		node := utils.NewNode(MainnetBootnodes[i%len(MainnetBootnodes)])
		err = udp.Ping(node)
		enr, err := udp.RequestENR(node)
		log.Println(err, enr, node.String())
		time.Sleep(1 * time.Second)
	}

}
