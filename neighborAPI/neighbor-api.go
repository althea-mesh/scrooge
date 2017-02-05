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
		SendMulticastUDP(*net.Interface, int, string) error
	}
}

func (self *NeighborAPI) Handlers(
	b []byte,
	iface *net.Interface,
) error {
	msg := strings.Split(string(b), " ")

	log.Println("received: " + string(b))

	if msg[0] == "scrooge_hello" {
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

	addr, err := net.ResolveUDPAddr("udp6", neighbor.ControlAddress)
	if err != nil {
		return err
	}

	err = self.SendHello(addr, iface, true)
	if err != nil {
		return err
	}
	return nil
}

func (self *NeighborAPI) SendHello(
	neighAddr *net.UDPAddr,
	iface *net.Interface,
	confirm bool,
) error {
	self.Account.Seqnum = self.Account.Seqnum + 1

	s, err := serialization.FmtHello(
		self.Account,
		self.Account.ControlAddresses[iface.Name],
		confirm,
	)
	if err != nil {
		return err
	}

	err = self.Network.SendUDP(neighAddr, s)
	if err != nil {
		return err
	}

	log.Println("sent: " + s)

	return nil
}

// func (self *NeighborAPI) SendTunnel(
// 	neighAddr *net.UDPAddr,
// 	iface *net.Interface,
// 	confirm bool,
// ) error {
// 	self.Account.Seqnum = self.Account.Seqnum + 1

// 	s, err := serialization.FmtTunnel(
// 		self.Account,
// 		self.Account.ControlAddresses[iface.Name],
// 		confirm,
// 	)
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

func (self *NeighborAPI) SendMcastHello(
	iface *net.Interface,
	port int,
) error {
	s, err := serialization.FmtHello(
		self.Account,
		self.Account.ControlAddresses[iface.Name],
		false,
	)
	if err != nil {
		return err
	}

	err = self.Network.SendMulticastUDP(iface, port, s)
	if err != nil {
		return err
	}

	self.Account.Seqnum = self.Account.Seqnum + 1

	return nil
}