package main

import (
	"github.com/CryptoProcessing/ethoover/ethserver"
	"github.com/CryptoProcessing/ethoover/utils"
	"github.com/ethereum/go-ethereum/crypto"
	ethlog "github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"log"
	"net"
	"time"
)

var RopstenBootnodes = []string{
	"enode://30b7ab30a01c124a6cceca36863ece12c4f5fa68e3ba9b0b51407ccc002eeed3b3102d20a88f1c1d3c3154e2449317b8ef95090e77b312d5cc39354f86d5d606@52.176.7.10:30303",    // US-Azure geth
	"enode://865a63255b3bb68023b6bffd5095118fcc13e79dcf014fe4e47e065c350c7cc72af2e53eff895f11ba1bbb6a2b33271c1116ee870f266618eadfc2e78aa7349c@52.176.100.77:30303",  // US-Azure parity
	"enode://6332792c4a00e3e4ee0926ed89e0d27ef985424d97b6a45bf0f23e51f0dcb5e66b875777506458aea7af6f9e4ffb69f43f3778ee73c81ed9d34c51c4b16b0b0f@52.232.243.152:30303", // Parity
	"enode://94c15d1b9e2fe7ce56e458b9a3b672ef11894ddedd0c6f247e0f1d3487f52b66208fb4aeb8179fce6e3a749ea93ed147c37976d67af557508d199d9594c35f09@192.81.208.223:30303", // @gpip
}

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
	//unhandled chan discover.ReadPacket
}

/*
func (srv *Server) setupConn(c *conn, flags connFlag, dialDest *enode.Node) error {
	// Prevent leftover pending conns from entering the handshake.

	// If dialing, figure out the remote public key.
	var dialPubkey *ecdsa.PublicKey
	if dialDest != nil {
		dialPubkey = new(ecdsa.PublicKey)
		if err := dialDest.Load((*enode.Secp256k1)(dialPubkey)); err != nil {
			err = errors.New("dial destination doesn't have a secp256k1 public key")
			srv.log.Trace("Setting up connection failed", "addr", c.fd.RemoteAddr(), "conn", c.flags, "err", err)
			return err
		}
	}

	// Run the RLPx handshake.
	remotePubkey, err := c.doEncHandshake(srv.PrivateKey, dialPubkey)
	if err != nil {
		srv.log.Trace("Failed RLPx handshake", "addr", c.fd.RemoteAddr(), "conn", c.flags, "err", err)
		return err
	}
	if dialDest != nil {
		// For dialed connections, check that the remote public key matches.
		if dialPubkey.X.Cmp(remotePubkey.X) != 0 || dialPubkey.Y.Cmp(remotePubkey.Y) != 0 {
			return DiscUnexpectedIdentity
		}
		c.node = dialDest
	} else {
		c.node = nodeFromConn(remotePubkey, c.fd)
	}
	clog := srv.log.New("id", c.node.ID(), "addr", c.fd.RemoteAddr(), "conn", c.flags)
	err = srv.checkpoint(c, srv.checkpointPostHandshake)
	if err != nil {
		clog.Trace("Rejected peer", "err", err)
		return err
	}

	// Run the capability negotiation handshake.
	phs, err := c.doProtoHandshake(srv.ourHandshake)
	if err != nil {
		clog.Trace("Failed p2p handshake", "err", err)
		return err
	}
	if id := c.node.ID(); !bytes.Equal(crypto.Keccak256(phs.ID), id[:]) {
		clog.Trace("Wrong devp2p handshake identity", "phsid", hex.EncodeToString(phs.ID))
		return DiscUnexpectedIdentity
	}
	c.caps, c.name = phs.Caps, phs.Name
	err = srv.checkpoint(c, srv.checkpointAddPeer)
	if err != nil {
		clog.Trace("Rejected peer", "err", err)
		return err
	}

	return nil
}*/

func main() {

	key, _ := crypto.GenerateKey()

	db, _ := enode.OpenDB("")
	addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		log.Fatalln(err)
	}
	bootnodesList := MainnetBootnodes

	bootnodesMap := make(map[string]*enode.Node)
	var bootNodes []*enode.Node
	for _, bn := range bootnodesList {
		bootNodes = append(bootNodes, utils.NewNode(bn))
		bootnodesMap[bn] = utils.NewNode(bn)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalln(err)
	}
	realaddr := conn.LocalAddr().(*net.UDPAddr)

	localNode := enode.NewLocalNode(db, key)

	localNode.SetFallbackUDP(realaddr.Port)
	localNode.SetFallbackIP(realaddr.IP)

	//unhandled := make(chan discover.ReadPacket, 100)

	sconn := &sharedUDPConn{
		conn,
		//unhandled,
	}

	log.Println(localNode.Node().IP(), localNode.Node().Pubkey())

	ethLogger := ethlog.New("node", "localhost")
	//ethLogger.SetHandler(ethlog.StdoutHandler)

	config := discover.Config{
		PrivateKey: key,
		Log:        ethLogger,
		Bootnodes:  bootNodes,
	}

	udp, err := discover.ListenUDP(sconn, localNode, config)
	log.Println(err, udp)

	var bootnodesListToCheck []string
	for len(bootnodesList) > 0 {
		bootnodesListToCheck = []string{}
		for _, v := range bootnodesList {
			bootnodesListToCheck = append(bootnodesListToCheck, v)
		}
		bootnodesList = []string{}
		for k, v := range bootnodesListToCheck {
			node := utils.NewNode(v)

			pingTime := time.Now()
			err = udp.Ping(node)
			if err != nil {

				ethLogger.Trace("Ping error", "err", err)
			} else {
				ethLogger.Debug("Ping", "time", time.Now().Sub(pingTime).Seconds(), "id", k)
			}

			nodes := udp.LookupPubkey(node.Pubkey())
			for i, n := range nodes {
				log.Println(i, n)
				if _, found := bootnodesMap[n.String()]; !found {
					bootnodesMap[n.String()] = n
					bootnodesList = append(bootnodesList, n.String())
				}
			}

			newServer := ethserver.NewEthServer(v)
			newServer.StartTestServer()
			//newServer.AddPeer(v)
			//newServer.GetPeers()
		}
	}

	for k, _ := range bootnodesMap {
		log.Println(k)
	}
	log.Println(len(bootnodesMap), "Nodes found")

}
