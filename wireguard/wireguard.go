package wireguard

import (
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"errors"

	"bytes"

	"github.com/incentivized-mesh-infrastructure/scrooge/types"
)

func Genkeys() (string, string, error) {
	privkey, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", "", err
	}

	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = bytes.NewReader(privkey)
	pubkey, err := cmd.Output()
	if err != nil {
		return "", "", err
	}

	return string(pubkey), string(privkey), nil
}

func execCommand(command string, args ...string) ([]byte, error) {
	stdout, stderr := bytes.Buffer{}, bytes.Buffer{}

	cmd := exec.Command(command, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	if err != nil {
		var message string

		if stderr.Len() == 0 {
			message = stdout.String()
		} else {
			message = stderr.String()
		}

		return nil, errors.New(
			"command `" + command + " " +
				strings.Join(args, " ") + "` failed. " + message)
	}

	return stdout.Bytes(), nil
}

func CreateTunnel(
	tunnel *types.Tunnel,
	tunnelPrivateKey string,
) error {
	_, err := execCommand("ip", "link", "add", "dev", tunnel.VirtualInterface.Name, "type", "wireguard")

	if err != nil {
		if regexp.MustCompile(`File exists`).MatchString(err.Error()) {
			_, err := execCommand("ip", "link", "del", tunnel.VirtualInterface.Name)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	privateKeyFile, err := ioutil.TempFile("", "example")
	if err != nil {
		return err
	}

	defer os.Remove(privateKeyFile.Name()) // clean up

	privateKeyFile.Chmod(0700)
	privateKeyFile.Chown(0, 0)

	_, err = privateKeyFile.Write([]byte(tunnelPrivateKey))
	if err != nil {
		return err
	}

	err = privateKeyFile.Close()
	if err != nil {
		return err
	}

	_, err = execCommand("wg", "set", tunnel.VirtualInterface.Name,
		"listen-port", strconv.FormatUint(uint64(tunnel.ListenPort), 10),
		"private-key", privateKeyFile.Name(),
		"peer", tunnel.PublicKey,
		"allowed-ips", "0.0.0.0",
		"endpoint", tunnel.Endpoint)
	if err != nil {
		return err
	}

	_, err = execCommand("ip", "link", "set", "up", tunnel.VirtualInterface.Name)
	if err != nil {
		return err
	}

	out, err := exec.Command("wg", "showconf", tunnel.VirtualInterface.Name).Output()
	if err != nil {
		return err
	}

	config, err := ParseConfig(string(out))
	if err != nil {
		return err
	}

	if config.PrivateKey != tunnelPrivateKey ||
		config.ListenPort != tunnel.ListenPort {
		return errors.New("Could not create tunnel")
	}

	return nil
}

type WireguardConfig struct {
	PrivateKey string
	ListenPort int
	Peer       struct {
		PublicKey  string
		AllowedIPs string
		Endpoint   string
	}
}

func ParseConfig(s string) (*WireguardConfig, error) {
	var config WireguardConfig

	config.PrivateKey = findFirstSubmatch(s, "PrivateKey")
	listenPort, err := strconv.ParseUint(findFirstSubmatch(s, "ListenPort"), 10, 64)
	if err != nil {
		return nil, err
	}
	config.ListenPort = int(listenPort)
	config.Peer.PublicKey = findFirstSubmatch(s, "PublicKey")
	config.Peer.AllowedIPs = findFirstSubmatch(s, "AllowedIPs")
	config.Peer.Endpoint = findFirstSubmatch(s, "Endpoint")

	return &config, nil
}

func findFirstSubmatch(s string, name string) string {
	re := regexp.MustCompile(name + " = (.*)")
	res := re.FindAllStringSubmatch(s, 1)
	return res[0][1]
}

// [Interface]
// PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
// ListenPort = 51820

// [Peer]
// PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
// Endpoint = 192.95.5.67:1234
// AllowedIPs = 10.192.122.3/32, 10.192.124.1/24

// [Interface]
// PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
// ListenPort = 51820

// [Peer]
// PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
// Endpoint = 192.95.5.67:1234
// AllowedIPs = 10.192.122.3/32, 10.192.124.1/24
