Scrooge is intended to allow nodes to create tunnels with neighbors on their network, then throttle those tunnels based on the receipt of cryptocurrency payments.

Neighbor discovery:

Scrooge can be run on one or more network interfaces. It intermittently broadcasts `scrooge_hello` messages on the link local multicast ipv6 address on a predetermined UDP port. It also listens for these messages on each of these interfaces.

### Scrooge hello message

`scrooge_hello <publicKey> <seq num> <signature>`

- PublicKey: base64 encoded ed25519 public key. This is used by neighbors to identify each other and sign messages, including the `scrooge_hello` message.
- Sequence number: Incremented with each hello to prevent playback attacks
- Signature: The signature of the publicKey over the fields of this message, concatenated as byte strings with no spaces (we may want to tweak this?)

When a node receives one of these messages: 
- It first checks the signature, and adds a record of this Neighbor if it does not already exist (neighbors are identified by public key). 
- It checks the SeqNum to prevent replay attack.
- It sends a `scrooge_hello_confirm` message.

### Scrooge hello confirm message
`scrooge_hello_confirm <publicKey> <seq num> <signature>`

When a node receives one of these messages: 
- It first checks the signature, and adds a record of this Neighbor if it does not already exist (neighbors are identified by public key). 
- It checks the SeqNum to prevent replay attack.
- It may start a tunnel and send a scrooge tunnel message as described below.

### Scrooge tunnel message

Sometimes a node wants to establish a tunnel with one of its neighbor nodes. Maybe it has just received a hello_confirm from this neighbor after it has broadcasted a hello, or maybe it needs to refresh the tunnel for some reason.

- It first stops and removes any existing tunnel with the neighbor. 
- It then starts a new tunnel on an available port and sends the message.

`scrooge_tunnel <publicKey> <tunnel publicKey> <tunnel endpoint> <seq num> <signature>`

When a node receives this message,
- It adds the tunnel publicKey and endpoint to the tunnel record for that node and starts a tunnel listening on an available port.
- It then sends a `scrooge_tunnel_confirm` message back.

### Scrooge tunnel confirm message

`scrooge_tunnel_confirm <publicKey> <tunnel publicKey> <tunnel endpoint> <seq num> <signature>`

This is the same as the `scrooge_tunnel` message, except that when a node receives it, it does not send a message back. This is to stop an infinite loop of `scrooge_tunnel` messages from occurring.
