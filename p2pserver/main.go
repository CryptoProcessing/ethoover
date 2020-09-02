package main

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/CryptoProcessing/ethoover/utils"
	"github.com/ethereum/go-ethereum/crypto"
	ethlog "github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
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

var globalKey *ecdsa.PrivateKey = nil

func newkey() *ecdsa.PrivateKey {
	if globalKey != nil {
		return globalKey
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		panic("couldn't generate key: " + err.Error())
	}
	globalKey = key
	return key
}
func startTestServer(remoteKey *ecdsa.PublicKey, pf func(*p2p.Peer)) *p2p.Server {
	targetNode := utils.NewNode("enode://006e0037a83ee46b93968f9c6c4a4208ea88c9c5c043c9a5775d42c8e17bb21730db26aa01e0d098db758bcb9f0a3c3c9c6a221dc8e06a4fcd14dc3123d90a9f@73.240.200.107:55818")

	bootNodes := []*enode.Node{targetNode}

	ethLogger := ethlog.New("ETHLog", "p2p")
	ethLogger.SetHandler(ethlog.StdoutHandler)

	config := p2p.Config{
		Name:           "test",
		MaxPeers:       10,
		ListenAddr:     "0.0.0.0:0",
		NoDiscovery:    false,
		NoDial:         false,
		BootstrapNodes: bootNodes,
		PrivateKey:     newkey(),
		Logger:         ethLogger,
	}

	server := &p2p.Server{
		Config: config,
	}
	if err := server.Start(); err != nil {
		log.Fatalf("Could not start server: %v", err)
	}
	return server
}

func main() {
	connected := make(chan *p2p.Peer)
	remid := &newkey().PublicKey
	srv := startTestServer(remid, func(p *p2p.Peer) {
		if p.ID() != enode.PubkeyToIDV4(remid) {
			log.Println("peer func called with wrong node id")
		}
		connected <- p
	})

	timeout := time.After(30 * time.Second)

	defer close(connected)
	//hosttargetNode := utils.NewNode("enode://006e0037a83ee46b93968f9c6c4a4208ea88c9c5c043c9a5775d42c8e17bb21730db26aa01e0d098db758bcb9f0a3c3c9c6a221dc8e06a4fcd14dc3123d90a9f@73.240.200.107:55818")
	targetNode := utils.NewNode(MainnetBootnodes[0])
	peerEventChan := make(chan *p2p.PeerEvent, 1)
	sub := srv.SubscribeEvents(peerEventChan)
	defer sub.Unsubscribe()

	//conn, err := net.DialTimeout("tcp", "73.240.200.107:55818", 5*time.Second)
	for _, n := range MainnetBootnodes {
		targetNode := utils.NewNode(n)

		host := fmt.Sprintf("%s:%d", targetNode.IP(), targetNode.UDP())
		conn, err := net.DialTimeout("tcp", host, 5*time.Second)
		if err != nil {
			log.Fatalf("could not dial: %v", err)
		} else {
			break
		}
		defer conn.Close()
	}

	srv.AddPeer(targetNode)
	peers := srv.Peers()
	for _, p := range peers {
		log.Println(p)
	}

	//for {
	select {
	case ev := <-peerEventChan:
		if ev.Type == p2p.PeerEventTypeAdd && ev.Peer == targetNode.ID() {
			log.Println("Success")
		}
		log.Println("Event")
	case <-timeout:
		log.Println("Timeout")
		break
	}

	//}
	log.Println("Exiting")

	time.Sleep(30 * time.Second)

	defer srv.Stop()

}
