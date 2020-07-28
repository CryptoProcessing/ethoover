package ethproto

import (
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"log"
)

var protocolLengths = map[uint]uint64{eth.ProtocolVersions[0]: 17, eth.ProtocolVersions[1]: 17, eth.ProtocolVersions[2]: 17}

func makeProtocol(version uint) p2p.Protocol {
	length, ok := protocolLengths[version]
	if !ok {
		panic("makeProtocol for unknown version")
	}

	return p2p.Protocol{
		Name:    "eth",
		Version: version,
		Length:  length,
		Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
			//return pm.runPeer(pm.newPeer(int(version), p, rw, pm.txpool.Get))
			msg, _ := rw.ReadMsg()
			buf := make([]byte, msg.Size)
			msg.Payload.Read(buf)
			log.Println("Run", p.ID(), msg.Code, string(buf))
			//rw.WriteMsg(msg)
			return nil
		},
		NodeInfo: func() interface{} {
			//return pm.NodeInfo()
			log.Println("Node Info")
			return nil
		},
		PeerInfo: func(id enode.ID) interface{} {
			/*if p := pm.peers.Peer(fmt.Sprintf("%x", id[:8])); p != nil {
				//return p.Info()
			}*/
			log.Println("Peer Info")
			return nil
		},
	}
}

func Protocols() []p2p.Protocol {

	protos := make([]p2p.Protocol, len(eth.ProtocolVersions))
	for i, vsn := range eth.ProtocolVersions {
		protos[i] = makeProtocol(vsn)
		//protos[i].Attributes = []enr.Entry{s.currentEthEntry()}
		//protos[i].DialCandidates = s.dialCandidates
	}
	return protos
}
