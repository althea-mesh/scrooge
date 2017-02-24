package serialization

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"

	"strconv"

	"github.com/agl/ed25519"
	"github.com/incentivized-mesh-infrastructure/scrooge/types"
)

// scrooge_hello[_confirm] <SourcePublicKey> <seqnum> <signature>
func FmtHelloMsg(
	msg types.HelloMessage,
	privateKey [ed25519.PrivateKeySize]byte,
) (string, error) {
	var msgType string

	if msg.Confirm {
		msgType = "scrooge_hello_confirm"
	} else {
		msgType = "scrooge_hello"
	}

	s := fmt.Sprintf(
		"%v %v %v %v",
		msgType,
		base64.StdEncoding.EncodeToString(msg.SourcePublicKey[:]),
		base64.StdEncoding.EncodeToString(msg.DestinationPublicKey[:]),
		msg.Seqnum,
	)

	sig := ed25519.Sign(&privateKey, []byte(s))

	return s + " " + base64.StdEncoding.EncodeToString(sig[:]), nil
}

func ParseHelloMsg(msg []string, confirm bool) (*types.HelloMessage, error) {
	messageMetadata, err := verifyMessage(msg)
	if err != nil {
		return nil, err
	}

	h := &types.HelloMessage{
		MessageMetadata: *messageMetadata,
		Confirm:         confirm,
	}

	log.Printf("parsed HelloMessage: %+v\n", h)

	return h, nil
}

// scrooge_tunnel[_confirm] <sourcePublicKey> <destinationPublicKey> <tunnel publicKey> <tunnel endpoint> <seq num> <signature>
func FmtTunnelMsg(
	msg types.TunnelMessage,
	privateKey [ed25519.PrivateKeySize]byte,
) (string, error) {
	var msgType string

	if msg.Confirm {
		msgType = "scrooge_tunnel_confirm"
	} else {
		msgType = "scrooge_tunnel"
	}

	s := fmt.Sprintf(
		"%v %v %v %v %v %v",
		msgType,
		base64.StdEncoding.EncodeToString(msg.SourcePublicKey[:]),
		base64.StdEncoding.EncodeToString(msg.DestinationPublicKey[:]),
		msg.TunnelPublicKey,
		msg.TunnelEndpoint,
		msg.Seqnum,
	)

	sig := ed25519.Sign(&privateKey, []byte(s))

	return s + " " + base64.StdEncoding.EncodeToString(sig[:]), nil
}

func ParseTunnelMsg(msg []string, confirm bool) (*types.TunnelMessage, error) {
	messageMetadata, err := verifyMessage(msg)
	if err != nil {
		return nil, err
	}

	m := &types.TunnelMessage{
		MessageMetadata: *messageMetadata,
		TunnelPublicKey: msg[3],
		TunnelEndpoint:  msg[4],
		Confirm:         confirm,
	}

	log.Printf("parsed TunnelMessage: %+v\n", m)

	return m, nil
}

func verifyMessage(msg []string) (*types.MessageMetadata, error) {
	sig, err := base64.StdEncoding.DecodeString(msg[len(msg)-1])
	if err != nil {
		return nil, err
	}
	signature := types.BytesToSignature(sig)

	spk, err := base64.StdEncoding.DecodeString(msg[1])
	if err != nil {
		return nil, err
	}
	sourcePublicKey := types.BytesToPublicKey(spk)

	dpk, err := base64.StdEncoding.DecodeString(msg[2])
	if err != nil {
		return nil, err
	}
	destinationPublicKey := types.BytesToPublicKey(dpk)

	msgWithOutSig := strings.Join(msg[:len(msg)-1], " ")
	fmt.Println(msgWithOutSig)
	if !ed25519.Verify(&sourcePublicKey, []byte(msgWithOutSig), &signature) {
		return nil, errors.New("signature not valid")
	}

	seqnum, err := strconv.ParseUint(msg[len(msg)-2], 10, 64)
	if err != nil {
		return nil, err
	}

	messageMetadata := types.MessageMetadata{
		SourcePublicKey:      sourcePublicKey,
		DestinationPublicKey: destinationPublicKey,
		Seqnum:               seqnum,
		Signature:            signature,
	}

	return &messageMetadata, nil
}
