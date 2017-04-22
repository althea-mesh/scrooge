package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"net"

	"io/ioutil"

	"github.com/agl/ed25519"
	"github.com/golang/glog"
	"github.com/incentivized-mesh-infrastructure/scrooge/neighborAPI"
	"github.com/incentivized-mesh-infrastructure/scrooge/network"
	"github.com/incentivized-mesh-infrastructure/scrooge/types"
	"github.com/incentivized-mesh-infrastructure/scrooge/wireguard"
)

func main() {
	genkeys := flag.Bool("genkeys", false, "Generate encryption keys and quit")

	ifi := flag.String("interface", "", "Physical network interface to operate on.")

	publicKeyFile := flag.String("publicKey", "", "PublicKey to sign messages to other nodes.")
	privateKeyFile := flag.String("privateKey", "", "PrivateKey to sign messages to other nodes.")

	flag.Parse()

	if *genkeys {
		publicKey, privateKey, err := wireguard.Genkeys()
		if err != nil {
			glog.Fatalln(err)
		}

		fmt.Printf(
			`
public key: %v
private vkey: %v
`,
			publicKey,
			privateKey,
		)

	} else {

		iface, err := net.InterfaceByName(*ifi)
		if err != nil {
			glog.Fatalln(err)
		}

		pubKey, err := readBase64File(*publicKeyFile)
		if err != nil {
			glog.Fatalln(err)
		}

		privKey, err := readBase64File(*privateKeyFile)
		if err != nil {
			glog.Fatalln(err)
		}

		network := network.Network{
			MulticastPort: 8481,
		}

		neighborAPI := neighborAPI.NeighborAPI{
			Neighbors: map[[ed25519.PublicKeySize]byte]*types.Neighbor{},
			Network:   &network,
			Account: &types.Account{
				PublicKey:  types.BytesToPublicKey(pubKey),
				PrivateKey: types.BytesToPrivateKey(privKey),
				Seqnum:     0,
			},
		}

		callback := func(err error) {
			if err != nil {
				glog.Fatalln(err)
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
			glog.Fatalln(err)
		}
		select {}
	}
}

func readBase64File(filename string) ([]byte, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(string(b))
}
