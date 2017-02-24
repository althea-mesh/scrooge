package network

import (
	"log"
	"net"
)

type Network struct {
	MulticastPort int
}

// McastListen listens on the multicast UDP address on a given interface.
func (self *Network) McastListen(
	iface *net.Interface,
	handlers func([]byte, *net.Interface) error,
	cb func(error),
) error {
	conn, err := net.ListenMulticastUDP(
		"udp6",
		iface,
		&net.UDPAddr{
			IP:   net.ParseIP("ff02::1"),
			Port: self.MulticastPort,
			Zone: iface.Name,
		},
	)
	if err != nil {
		return err
	}

	for {
		var b = make([]byte, 1500)
		offset, _, err := conn.ReadFromUDP(b)

		if err != nil {
			cb(err)
			continue
		}
		cb(handlers(b[:offset], iface))
	}

	return nil
}

func (self *Network) SendUDP(
	addr *net.UDPAddr,
	s string,
) error {
	conn, err := net.DialUDP(
		"udp6",
		nil,
		addr,
	)
	if err != nil {
		return err
	}

	defer conn.Close()

	_, err = conn.Write([]byte(s))
	if err != nil {
		return err
	}

	log.Println("sent: " + s)
	return nil
}

func (self *Network) SendMulticastUDP(
	iface *net.Interface,
	s string,
) error {
	err := self.SendUDP(&net.UDPAddr{
		IP:   net.ParseIP("ff02::1"),
		Port: self.MulticastPort,
		Zone: iface.Name,
	}, s)
	if err != nil {
		return err
	}
	return nil
}
