package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/agl/ed25519"
	"github.com/incentivized-mesh-infrastructure/scrooge/neighborAPI"
	"github.com/incentivized-mesh-infrastructure/scrooge/network"
	"github.com/incentivized-mesh-infrastructure/scrooge/types"
)

func main() {
	genkeys := flag.Bool("genkeys", false, "Generate encryption keys and quit")

	ifi := flag.String("interface", "", "Physical network interface to operate on.")

	publicKey := flag.String("publicKey", "", "PublicKey to sign messages to other nodes.")
	privateKey := flag.String("privateKey", "", "PrivateKey to sign messages to other nodes.")

	tunnelPublicKey := flag.String("tunnelPublicKey", "", "PublicKey of authenticated tunnel")
	tunnelPrivateKey := flag.String("tunnelPrivateKey", "", "PrivateKey of authenticated tunnel")

	flag.Parse()

	if *genkeys {
		scroogePubkey, scroogePrivkey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalln(err)
		}

		// fmt.Printf("%#v %#v", scroogePubkey, scroogePrivkey)

		wireguardPubkey, wireguardPrivkey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalln(err)
		}

		fmt.Printf(
			`scrooge pubkey: %v
scrooge privkey: %v
wireguard pubkey: %v
wireguard privkey: %v
`,
			base64.StdEncoding.EncodeToString(scroogePubkey[:]),
			base64.StdEncoding.EncodeToString(scroogePrivkey[:]),
			base64.StdEncoding.EncodeToString(wireguardPubkey[:]),
			base64.StdEncoding.EncodeToString(wireguardPrivkey[:]),
		)

	} else {

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

		network := network.Network{
			MulticastPort: 8481,
		}

		neighborAPI := neighborAPI.NeighborAPI{
			Neighbors: map[[ed25519.PublicKeySize]byte]*types.Neighbor{},
			Network:   &network,
			Account: &types.Account{
				PublicKey:        types.BytesToPublicKey(pubKey),
				PrivateKey:       types.BytesToPrivateKey(privKey),
				TunnelPublicKey:  *tunnelPublicKey,
				TunnelPrivateKey: *tunnelPrivateKey,
				Seqnum:           0,
			},
		}

		callback := func(err error) {
			if err != nil {
				log.Fatalln(err)
			}
		}
		go network.McastListen(
			iface,
			neighborAPI.Handlers,
			callback,
		)

		err = neighborAPI.SendHelloMsg(
			iface,
			false,
		)
		if err != nil {
			log.Fatalln(err)
		}
		select {}
	}
}
