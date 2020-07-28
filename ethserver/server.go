package ethserver

import (
	"crypto/ecdsa"
	"github.com/CryptoProcessing/ethoover/ethproto"
	"github.com/CryptoProcessing/ethoover/utils"
	"github.com/ethereum/go-ethereum/event"
	ethlog "github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"log"
)

type EthServer struct {
	Node          *enode.Node
	Key           *ecdsa.PrivateKey
	Log           ethlog.Logger
	Config        p2p.Config
	Server        *p2p.Server
	PeerEventChan chan *p2p.PeerEvent
	StopChan      chan bool
	Subscription  event.Subscription
}

func PeerWorker(srv *EthServer) {
	for {
		select {
		case ev := <-srv.PeerEventChan:
			log.Println("Peer event", ev)
			srv.GetPeers()
		case <-srv.StopChan:
			log.Println("Stop event")
			return
		}
	}
}

func (srv *EthServer) StartTestServer() {
	srv.Server = &p2p.Server{
		Config: srv.Config,
	}

	if err := srv.Server.Start(); err != nil {
		log.Fatalf("Could not start server: %v", err)
	}
	srv.Subscription = srv.Server.SubscribeEvents(srv.PeerEventChan)

	go PeerWorker(srv)
}

func (srv *EthServer) StopServer() {
	srv.StopChan <- true
	srv.Subscription.Unsubscribe()
	srv.Server.Stop()
}

func NewEthServer(bootNodeUri string) *EthServer {
	key := utils.NewKey()
	ethLogger := ethlog.New("Node", bootNodeUri)
	//ethLogger.SetHandler(ethlog.StdoutHandler)

	config := p2p.Config{
		Name:            "test",
		MaxPeers:        2,
		ListenAddr:      "0.0.0.0:0",
		NoDiscovery:     false,
		NoDial:          false,
		BootstrapNodes:  []*enode.Node{utils.NewNode(bootNodeUri)},
		PrivateKey:      key,
		Logger:          ethLogger,
		EnableMsgEvents: true,
		Protocols:       ethproto.Protocols(),
	}

	return &EthServer{
		Config:        config,
		Key:           utils.NewKey(),
		Log:           ethLogger,
		PeerEventChan: make(chan *p2p.PeerEvent, 100),
	}
}

func (srv *EthServer) AddPeer(uri string) {
	targetNode := utils.NewNode(uri)
	srv.Server.AddTrustedPeer(targetNode)
}

func (srv *EthServer) GetPeers() {
	peers := srv.Server.Peers()
	log.Println("Peers ", len(peers))
	for i, v := range peers {
		log.Printf("#%d : %s", i, v.Name())
	}
}
