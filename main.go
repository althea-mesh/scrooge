package main

import (
	"encoding/base64"
	"flag"
	"log"
	"net"

	"github.com/agl/ed25519"
	"github.com/incentivized-mesh-infrastructure/scrooge/neighborAPI"
	"github.com/incentivized-mesh-infrastructure/scrooge/network"
	"github.com/incentivized-mesh-infrastructure/scrooge/types"
)

func main() {

	listen := flag.Bool("l", false, "Listen for hellos")

	ifi := flag.String("interface", "", "Physical network interface to operate on.")
	controlAddress := flag.String("controlAddress", "", "Control address to listen for communication from other nodes.")

	publicKey := flag.String("publicKey", "", "PublicKey to sign messages to other nodes.")
	privateKey := flag.String("privateKey", "", "PrivateKey to sign messages to other nodes.")

	tunnelPublicKey := flag.String("tunnelPublicKey", "", "PublicKey of authenticated tunnel")
	tunnelPrivateKey := flag.String("tunnelPrivateKey", "", "PrivateKey of authenticated tunnel")

	flag.Parse()

	iface, err := net.InterfaceByName(*ifi)
	if err != nil {
		log.Fatalln(err)
	}

	pubKey, err := base64.StdEncoding.DecodeString(*publicKey)
	if err != nil {
		log.Fatalln(err)
	}

	privKey, err := base64.StdEncoding.DecodeString(*privateKey)
	if err != nil {
		log.Fatalln(err)
	}

	neighborAPI := neighborAPI.NeighborAPI{
		Neighbors: map[[ed25519.PublicKeySize]byte]*types.Neighbor{},
		Account: &types.Account{
			PublicKey:  types.BytesToPublicKey(pubKey),
			PrivateKey: types.BytesToPrivateKey(privKey),
			ControlAddresses: map[string]net.UDPAddr{
				(iface.Name): net.UDPAddr{
					IP:   net.ParseIP(*controlAddress),
					Port: 8000,
				},
			},
			TunnelPublicKey:  *tunnelPublicKey,
			TunnelPrivateKey: *tunnelPrivateKey,
			Seqnum:           0,
		},
	}

	network := network.Network{}

	if *listen {
		log.Println("listen")
		callback := func(err error) {
			if err != nil {
				log.Fatalln(err)
			}
		}
		err := network.McastListen(
			8481,
			iface,
			neighborAPI.Handlers,
			callback,
		)
		if err != nil {
			log.Fatalln(err)
		}
	} else {
		log.Println("hello")
		neighborAPI.SendMcastHello(
			iface,
			8481,
		)
	}
}
