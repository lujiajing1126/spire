package peertracker

import (
	"io"
	"net"

	"github.com/sirupsen/logrus"
)

var _ net.Listener = &Listener{}

type ListenerFactory struct {
	Log               logrus.FieldLogger
	NewTracker        func(log logrus.FieldLogger) (PeerTracker, error)
	ListenerFactoryOS // OS specific
}

func (lf *ListenerFactory) Listen(network string, laddr *net.TCPAddr) (*Listener, error) {
	if lf.NewTCPListener == nil {
		lf.NewTCPListener = net.ListenTCP
	}
	if lf.NewTracker == nil {
		lf.NewTracker = NewTracker
	}
	if lf.Log == nil {
		lf.Log = newNoopLogger()
	}
	return lf.listenTCP(network, laddr)
}

func (lf *ListenerFactory) listenTCP(network string, laddr *net.TCPAddr) (*Listener, error) {
	l, err := lf.NewTCPListener(network, laddr)
	if err != nil {
		return nil, err
	}

	tracker, err := lf.NewTracker(lf.Log)
	if err != nil {
		l.Close()
		return nil, err
	}

	return &Listener{
		l:       l,
		Tracker: tracker,
		log:     lf.Log,
	}, nil
}

type Listener struct {
	l       net.Listener
	log     logrus.FieldLogger
	Tracker PeerTracker
}

func newNoopLogger() *logrus.Logger {
	logger := logrus.New()
	logger.Out = io.Discard
	return logger
}

func (l *Listener) Accept() (net.Conn, error) {
	for {
		var caller CallerInfo
		var err error

		conn, err := l.l.Accept()
		if err != nil {
			return conn, err
		}

		// Support future Listener types
		switch conn.RemoteAddr().Network() {
		case "unix":
			caller, err = CallerFromUDSConn(conn)
		case "pipe":
			caller, err = CallerFromNamedPipeConn(conn)
		default:
			err = ErrUnsupportedTransport
		}

		if err != nil {
			l.log.WithError(err).Warn("Connection failed during accept")
			conn.Close()
			continue
		}

		watcher, err := l.Tracker.NewWatcher(caller)
		if err != nil {
			l.log.WithError(err).Warn("Connection failed during accept")
			conn.Close()
			continue
		}

		wrappedConn := &Conn{
			Conn: conn,
			Info: AuthInfo{
				Caller:  caller,
				Watcher: closeOnIsAliveErr{Watcher: watcher, conn: conn},
			},
		}

		return wrappedConn, nil
	}
}

func (l *Listener) Close() error {
	l.Tracker.Close()
	return l.l.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.l.Addr()
}

type closeOnIsAliveErr struct {
	Watcher
	conn io.Closer
}

func (w closeOnIsAliveErr) IsAlive() error {
	err := w.Watcher.IsAlive()
	if err != nil {
		_ = w.conn.Close()
	}
	return err
}
