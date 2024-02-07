//go:build !windows

package endpoints

import (
	"fmt"
	"net"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/spiffe/spire/pkg/common/peertracker"
)

func createUDSListener(log logrus.FieldLogger, addr net.Addr) (net.Listener, error) {
	// Remove uds if already exists
	os.Remove(addr.String())

	unixListener := &peertracker.ListenerFactory{
		Log: log,
	}

	unixAddr, ok := addr.(*net.UnixAddr)
	if !ok {
		return nil, fmt.Errorf("create UDS listener: address is type %T, not net.UnixAddr", addr)
	}
	l, err := unixListener.ListenUnix(addr.Network(), unixAddr)
	if err != nil {
		return nil, fmt.Errorf("create UDS listener: %w", err)
	}

	if err := os.Chmod(addr.String(), os.ModePerm); err != nil {
		return nil, fmt.Errorf("unable to change UDS permissions: %w", err)
	}
	return l, nil
}

func (e *Endpoints) createListener() (net.Listener, error) {
	return e.createListenerFor(e.addr)
}

func (e *Endpoints) createListenerFor(addr net.Addr) (net.Listener, error) {
	switch addr.Network() {
	case "unix":
		return createUDSListener(e.log, addr)
	case "tcp":
		return createTCPListener(e.log, addr)
	case "pipe":
		return nil, peertracker.ErrUnsupportedPlatform
	default:
		return nil, net.UnknownNetworkError(addr.Network())
	}
}
