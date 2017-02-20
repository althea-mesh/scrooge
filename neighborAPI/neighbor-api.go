package neighborAPI

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/agl/ed25519"
	"github.com/incentivized-mesh-infrastructure/scrooge/serialization"
	"github.com/incentivized-mesh-infrastructure/scrooge/types"
)

type NeighborAPI struct {
	Neighbors map[[ed25519.PublicKeySize]byte]*types.Neighbor
	Account   *types.Account
	Network   interface {
		SendBroadcastEthernet(
			iface *net.Interface,
			s string,
		) error
	}
}

func (self *NeighborAPI) Handlers(
	b []byte,
	iface *net.Interface,
) error {
	msg := strings.Split(string(b), " ")

	log.Println("received: " + string(b))

	if msg[0] == "scrooge_hello" || msg[0] == "scrooge_hello_confirm" {
		return self.helloHandler(msg, iface)
	}

	return errors.New("unrecognized message type")
}

func (self *NeighborAPI) helloHandler(
	msg []string,
	iface *net.Interface,
) error {
	helloMessage, err := serialization.ParseHello(msg)
	if err != nil {
		return err
	}

	neighbor := self.Neighbors[helloMessage.PublicKey]
	if neighbor == nil {
		neighbor = &types.Neighbor{
			PublicKey: helloMessage.PublicKey,
		}
		self.Neighbors[helloMessage.PublicKey] = neighbor
	}

	if neighbor.Seqnum >= helloMessage.Seqnum {
		return errors.New(fmt.Sprint("sequence number too low"))
	}

	neighbor.Seqnum = helloMessage.Seqnum
	neighbor.ControlAddress = helloMessage.ControlAddress

	if !helloMessage.Confirm {
		err = self.SendHello(iface, true)
		if err != nil {
			return err
		}
	}
	return nil
}

// func (self *NeighborAPI) SendHello(
// 	neighAddr *net.UDPAddr,
// 	iface *net.Interface,
// 	confirm bool,
// ) error {
// 	self.Account.Seqnum = self.Account.Seqnum + 1
// 	controlAddress := self.Account.ControlAddresses[iface.Name]

// 	msg := types.HelloMessage{
// 		MessageMetadata: types.MessageMetadata{
// 			Seqnum:    self.Account.Seqnum,
// 			PublicKey: self.Account.PublicKey,
// 		},
// 		ControlAddress: controlAddress,
// 		Confirm:        confirm,
// 	}

// 	s, err := serialization.FmtHello(msg, self.Account.PrivateKey)
// 	if err != nil {
// 		return err
// 	}

// 	err = self.Network.SendUDP(neighAddr, s)
// 	if err != nil {
// 		return err
// 	}

// 	log.Println("sent: " + s)

// 	return nil
// }

// func (self *NeighborAPI) SendMcastHello(
// 	iface *net.Interface,
// 	port int,
// ) error {
// 	self.Account.Seqnum = self.Account.Seqnum + 1
// 	controlAddress := self.Account.ControlAddresses[iface.Name]

// 	msg := types.HelloMessage{
// 		MessageMetadata: types.MessageMetadata{
// 			Seqnum:    self.Account.Seqnum,
// 			PublicKey: self.Account.PublicKey,
// 		},
// 		ControlAddress: controlAddress,
// 		Confirm:        false,
// 	}

// 	s, err := serialization.FmtHello(msg, self.Account.PrivateKey)
// 	if err != nil {
// 		return err
// 	}

// 	err = self.Network.SendMulticastUDP(iface, port, s)
// 	if err != nil {
// 		return err
// 	}

// 	self.Account.Seqnum = self.Account.Seqnum + 1

// 	return nil
// }

func (self *NeighborAPI) SendHello(
	iface *net.Interface,
	confirm bool,
) error {
	self.Account.Seqnum = self.Account.Seqnum + 1
	controlAddress := self.Account.ControlAddresses[iface.Name]

	msg := types.HelloMessage{
		MessageMetadata: types.MessageMetadata{
			Seqnum:    self.Account.Seqnum,
			PublicKey: self.Account.PublicKey,
		},
		ControlAddress: controlAddress,
		Confirm:        confirm,
	}

	s, err := serialization.FmtHello(msg, self.Account.PrivateKey)
	if err != nil {
		return err
	}

	err = self.Network.SendBroadcastEthernet(iface, s)
	if err != nil {
		return err
	}

	self.Account.Seqnum = self.Account.Seqnum + 1

	return nil
}

func (self *NeighborAPI) SendTunnel(
	neighborPublicKey [ed25519.PublicKeySize]byte,
	iface *net.Interface,
	confirm bool,
) error {
	self.Account.Seqnum = self.Account.Seqnum + 1
	neighbor := self.Neighbors[neighborPublicKey]

	msg := types.TunnelMessage{
		MessageMetadata: types.MessageMetadata{
			PublicKey: self.Account.PublicKey,
			Seqnum:    self.Account.Seqnum,
		},
		TunnelEndpoint:  neighbor.Tunnel.Endpoint,
		TunnelPublicKey: neighbor.Tunnel.PublicKey,
		Confirm:         confirm,
	}

	s, err := serialization.FmtTunnel(
		msg,
		self.Account.PrivateKey,
	)
	if err != nil {
		return err
	}

	err = self.Network.SendBroadcastEthernet(iface, s)
	if err != nil {
		return err
	}

	log.Println("sent: " + s)

	return nil
}
