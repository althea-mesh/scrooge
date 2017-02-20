package network

import (
	"log"
	"net"

	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/raw"
)

type Network struct{}

func (self *Network) ListenEthernet(
	iface *net.Interface,
	handlers func([]byte, *net.Interface) error,
	cb func(error),
) error {
	conn, err := raw.ListenPacket(
		iface,
		0x0806,
	)
	if err != nil {
		return err
	}

	defer conn.Close()

	for {
		var b = make([]byte, 1500)
		offset, _, err := conn.ReadFrom(b)

		if err != nil {
			cb(err)
			continue
		}
		cb(handlers(b[:offset], iface))
	}

	return nil
}

func (self *Network) SendEthernet(
	iface *net.Interface,
	addr *raw.Addr,
	s string,
) error {
	frame := &ethernet.Frame{
		Destination: addr.HardwareAddr,
		Payload:     []byte(s),
	}

	b, err := frame.MarshalBinary()

	conn, err := raw.ListenPacket(
		iface,
		0x0806,
	)
	if err != nil {
		return err
	}

	defer conn.Close()

	_, err = conn.WriteTo(b, addr)
	if err != nil {
		return err
	}

	log.Println("sent: " + s)
	return nil
}

func (self *Network) SendBroadcastEthernet(
	iface *net.Interface,
	s string,
) error {
	addr, err := net.ParseMAC("FF:FF:FF:FF:FF:FF")
	if err != nil {
		return err
	}

	err = self.SendEthernet(iface, &raw.Addr{HardwareAddr: addr}, s)
	if err != nil {
		return err
	}
	return nil
}

// McastListen listens on the multicast UDP address on a given interface.
func (self *Network) McastListen(
	port int,
	iface *net.Interface,
	handlers func([]byte, *net.Interface) error,
	cb func(error),
) error {
	conn, err := net.ListenMulticastUDP(
		"udp6",
		iface,
		&net.UDPAddr{
			IP:   net.ParseIP("ff02::1"),
			Port: port,
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

func (self *Network) UnicastListen(
	addr *net.UDPAddr,
	iface *net.Interface,
	handlers func([]byte, *net.Interface) error,
	cb func(error),
) error {
	conn, err := net.ListenUDP("udp6", addr)
	if err != nil {
		return err
	}

	defer conn.Close()

	for {
		var b []byte
		_, _, err := conn.ReadFromUDP(b)
		if err != nil {
			cb(err)
			continue
		}
		cb(handlers(b, iface))
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
	port int,
	s string,
) error {
	err := self.SendUDP(&net.UDPAddr{
		IP:   net.ParseIP("ff02::1"),
		Port: port,
		Zone: iface.Name,
	}, s)
	if err != nil {
		return err
	}
	return nil
}
