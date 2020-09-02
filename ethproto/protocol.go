package ethproto

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/eth"
	ethlog "github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"log"
	"math/big"
)

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
			p.Log().SetHandler(ethlog.StdoutHandler)
			/*

				peer := newPeer(int(version), p, rw, func (hash common.Hash) *types.Transaction{
						log.Println("newPeer", hash)
						return nil
				})
				peer.Log().SetHandler(ethlog.StdoutHandler)

				peer.Handshake(1, big.NewInt(0), common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"), common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
					forkid.ID{
						Hash: [4]byte{8, 42, 36, 128},
						Next: 0,
					},
					func (id forkid.ID) error {
						log.Println("forkfilter", id)
						return nil
					})
				caps := peer.Caps()
				for _,c := range(caps){
					log.Println(c.Name, c.Version, c.String())
				}
				for true {
					time.Sleep(1 * time.Second)
				}

			*/

			for true {
				msg, _ := rw.ReadMsg()
				if msg.Size == 0 {
					continue
				}

				var data statusData
				//msg.Payload.Read()Decode(&data)
				log.Println("Run", p.ID(), msg.Code, msg.Size)
				err := msg.Decode(&data)
				log.Println(data)
				if data.NetworkID != 1 {
					return nil
				}
				//buf := make([]byte, msg.Size)
				//msg.Payload.Read(buf)
				//payload, _ := ioutil.ReadAll(msg.Payload)
				//err := rlp.Decode(msg.Payload, &data)
				//size, r, err := rlp.EncodeToReader(buf)
				log.Println("RLP", err, data)
				//p2p.SendItems(rw, 0, 0)

				p2p.Send(rw, msg.Code,
					&statusData{
						ProtocolVersion: uint32(data.ProtocolVersion),
						NetworkID:       1,
						TD:              big.NewInt(0),
						Head:            common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
						Genesis:         common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
						ForkID:          data.ForkID,
					})
			}
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
	/*for i, vsn := range eth.ProtocolVersions {
		protos[i] = makeProtocol(vsn)
		//protos[i].Attributes = []enr.Entry{s.currentEthEntry()}
		//protos[i].DialCandidates = s.dialCandidates
	}*/
	protos[0] = makeProtocol(ProtocolVersions[1])
	return protos
}
