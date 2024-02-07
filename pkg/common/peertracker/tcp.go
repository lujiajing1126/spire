package peertracker

import (
	"net"
)

func CallerFromTCPConn(conn net.Conn) (CallerInfo, error) {
	var info CallerInfo

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return info, ErrInvalidConnection
	}

	rawconn, err := tcpConn.SyscallConn()
	if err != nil {
		return info, err
	}

	ctrlErr := rawconn.Control(func(fd uintptr) {
		info, err = getCallerInfoFromFileDescriptor(fd)
	})
	if ctrlErr != nil {
		return info, ctrlErr
	}
	if err != nil {
		return info, err
	}

	info.Addr = conn.RemoteAddr()
	return info, nil
}
