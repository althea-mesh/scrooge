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
		SendUDP(*net.UDPAddr, string) error
		SendMulticastUDP(*net.Interface, string) error
	}
}

func (self *NeighborAPI) Handlers(
	b []byte,
	iface *net.Interface,
) error {
	msg := strings.Split(string(b), " ")

	log.Println("received: " + string(b))

	switch msg[0] {
	case "scrooge_hello":
		return self.helloMsgHandler(msg, iface, false)
	case "scrooge_hello_confirm":
		return self.helloMsgHandler(msg, iface, true)
	case "scrooge_tunnel":
		return self.tunnelMsgHandler(msg, iface, false)
	case "scrooge_tunnel_confirm":
		return self.tunnelMsgHandler(msg, iface, true)
	}

	return errors.New("unrecognized message type")
}

func (self *NeighborAPI) helloMsgHandler(
	msg []string,
	iface *net.Interface,
	confirm bool,
) error {
	helloMessage, err := serialization.ParseHelloMsg(msg, confirm)
	if err != nil {
		return err
	}

	if helloMessage.SourcePublicKey == self.Account.PublicKey {
		return nil
	}

	neighbor := self.Neighbors[helloMessage.SourcePublicKey]
	if neighbor == nil {
		neighbor = &types.Neighbor{
			PublicKey: helloMessage.SourcePublicKey,
		}
		self.Neighbors[helloMessage.SourcePublicKey] = neighbor
	}

	if neighbor.Seqnum >= helloMessage.Seqnum {
		return errors.New(fmt.Sprint("sequence number too low"))
	}

	neighbor.Seqnum = helloMessage.Seqnum

	if !helloMessage.Confirm {
		err = self.SendHelloMsg(iface, true)
		if err != nil {
			return err
		}
	}
	return nil
}

func (self *NeighborAPI) tunnelMsgHandler(
	msg []string,
	iface *net.Interface,
	confirm bool,
) error {
	tunnelMessage, err := serialization.ParseTunnelMsg(msg, confirm)
	if err != nil {
		return err
	}

	if tunnelMessage.SourcePublicKey == self.Account.PublicKey ||
		tunnelMessage.DestinationPublicKey != self.Account.PublicKey {
		return nil
	}

	neighbor := self.Neighbors[tunnelMessage.SourcePublicKey]
	if neighbor == nil {
		neighbor = &types.Neighbor{
			PublicKey: tunnelMessage.SourcePublicKey,
		}
		self.Neighbors[tunnelMessage.SourcePublicKey] = neighbor
	}

	if neighbor.Seqnum >= tunnelMessage.Seqnum {
		return errors.New(fmt.Sprint("sequence number too low"))
	}

	neighbor.Seqnum = tunnelMessage.Seqnum

	if !tunnelMessage.Confirm {
		err = self.SendHelloMsg(iface, true)
		if err != nil {
			return err
		}
	}
	return nil
}

func (self *NeighborAPI) SendHelloMsg(
	iface *net.Interface,
	confirm bool,
) error {
	self.Account.Seqnum = self.Account.Seqnum + 1

	msg := types.HelloMessage{
		MessageMetadata: types.MessageMetadata{
			Seqnum:          self.Account.Seqnum,
			SourcePublicKey: self.Account.PublicKey,
		},
		Confirm: confirm,
	}

	s, err := serialization.FmtHelloMsg(msg, self.Account.PrivateKey)
	if err != nil {
		return err
	}

	err = self.Network.SendMulticastUDP(iface, s)
	if err != nil {
		return err
	}

	log.Println("sent: " + s)

	return nil
}

func (self *NeighborAPI) SendTunnelMsg(
	neighborPublicKey [ed25519.PublicKeySize]byte,
	iface *net.Interface,
	confirm bool,
) error {
	self.Account.Seqnum = self.Account.Seqnum + 1
	neighbor := self.Neighbors[neighborPublicKey]

	msg := types.TunnelMessage{
		MessageMetadata: types.MessageMetadata{
			SourcePublicKey:      self.Account.PublicKey,
			DestinationPublicKey: neighborPublicKey,
			Seqnum:               self.Account.Seqnum,
		},
		TunnelEndpoint:  neighbor.Tunnel.Endpoint,
		TunnelPublicKey: neighbor.Tunnel.PublicKey,
		Confirm:         confirm,
	}

	s, err := serialization.FmtTunnelMsg(
		msg,
		self.Account.PrivateKey,
	)
	if err != nil {
		return err
	}

	err = self.Network.SendMulticastUDP(iface, s)
	if err != nil {
		return err
	}

	log.Println("sent: " + s)

	return nil
}
