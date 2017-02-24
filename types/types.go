package types

import "net"
import "github.com/agl/ed25519"

// Internal types

type Account struct {
	PublicKey  [ed25519.PublicKeySize]byte
	PrivateKey [ed25519.PrivateKeySize]byte
	Seqnum     uint64
	// TunnelAddresses  map[string]net.UDPAddr
	TunnelPublicKey  string
	TunnelPrivateKey string
}

type Neighbor struct {
	PublicKey      [ed25519.PublicKeySize]byte
	Seqnum         uint64
	BillingDetails struct {
		PaymentAddress string
	}
	Tunnel
}

type Tunnel struct {
	PublicKey        string
	ListenPort       int           // Every tunnel needs to listen on a different port
	Endpoint         string        // This is the tunnel endpoint on the Neighbor
	VirtualInterface net.Interface // virtual interface created by the tunnel
}

// Message types
type MessageMetadata struct {
	SourcePublicKey      [ed25519.PublicKeySize]byte
	DestinationPublicKey [ed25519.PublicKeySize]byte
	Seqnum               uint64
	Signature            [ed25519.SignatureSize]byte
}

type HelloMessage struct {
	MessageMetadata
	Confirm bool
}

type TunnelMessage struct {
	MessageMetadata
	TunnelPublicKey string
	TunnelEndpoint  string
	Confirm         bool
}

// Utils

func BytesToPublicKey(bytes []byte) [ed25519.PublicKeySize]byte {
	var publicKey [ed25519.PublicKeySize]byte
	copy(publicKey[:], bytes)
	return publicKey
}

func BytesToPrivateKey(bytes []byte) [ed25519.PrivateKeySize]byte {
	var privateKey [ed25519.PrivateKeySize]byte
	copy(privateKey[:], bytes)
	return privateKey
}

func BytesToSignature(bytes []byte) [ed25519.SignatureSize]byte {
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], bytes)
	return signature
}
