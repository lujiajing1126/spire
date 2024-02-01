package endpoints

import (
	"context"
	"errors"
	"net"
	"time"

	secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/sirupsen/logrus"
	workload_pb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	healthv1 "github.com/spiffe/spire/pkg/agent/api/health/v1"
	"github.com/spiffe/spire/pkg/agent/endpoints/sdsv3"
	"github.com/spiffe/spire/pkg/agent/endpoints/workload"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
)

const (
	// This is the maximum amount of time an agent connection may exist before
	// the server sends a hangup request. This enables agents to more dynamically
	// route to the server in the case of a change in DNS membership.
	defaultMaxConnectionAge = 3 * time.Minute
)

type Server interface {
	ListenAndServe(ctx context.Context) error
}

type Endpoints struct {
	addr              net.Addr
	log               logrus.FieldLogger
	metrics           telemetry.Metrics
	workloadAPIServer workload_pb.SpiffeWorkloadAPIServer
	sdsv3Server       secret_v3.SecretDiscoveryServiceServer
	healthServer      grpc_health_v1.HealthServer

	hooks struct {
		// test hook used to indicate that is listening
		listening chan struct{}
	}
}

func New(c Config) *Endpoints {
	attestor := PeerTrackerAttestor{Attestor: c.Attestor}

	if c.newWorkloadAPIServer == nil {
		c.newWorkloadAPIServer = func(c workload.Config) workload_pb.SpiffeWorkloadAPIServer {
			return workload.New(c)
		}
	}
	if c.newSDSv3Server == nil {
		c.newSDSv3Server = func(c sdsv3.Config) secret_v3.SecretDiscoveryServiceServer {
			return sdsv3.New(c)
		}
	}
	if c.newHealthServer == nil {
		c.newHealthServer = func(c healthv1.Config) grpc_health_v1.HealthServer {
			return healthv1.New(c)
		}
	}

	allowedClaims := make(map[string]struct{}, len(c.AllowedForeignJWTClaims))
	for _, claim := range c.AllowedForeignJWTClaims {
		allowedClaims[claim] = struct{}{}
	}

	workloadAPIServer := c.newWorkloadAPIServer(workload.Config{
		Manager:                       c.Manager,
		Attestor:                      attestor,
		AllowUnauthenticatedVerifiers: c.AllowUnauthenticatedVerifiers,
		AllowedForeignJWTClaims:       allowedClaims,
		TrustDomain:                   c.TrustDomain,
	})

	sdsv3Server := c.newSDSv3Server(sdsv3.Config{
		Attestor:                    attestor,
		Manager:                     c.Manager,
		DefaultSVIDName:             c.DefaultSVIDName,
		DefaultBundleName:           c.DefaultBundleName,
		DefaultAllBundlesName:       c.DefaultAllBundlesName,
		DisableSPIFFECertValidation: c.DisableSPIFFECertValidation,
	})

	healthServer := c.newHealthServer(healthv1.Config{
		Addr: c.BindAddr,
	})

	return &Endpoints{
		addr:              c.BindAddr,
		log:               c.Log,
		metrics:           c.Metrics,
		workloadAPIServer: workloadAPIServer,
		sdsv3Server:       sdsv3Server,
		healthServer:      healthServer,
	}
}

func (e *Endpoints) ListenAndServe(ctx context.Context) error {
	unaryInterceptor, streamInterceptor := middleware.Interceptors(
		Middleware(e.log, e.metrics),
	)

	server := grpc.NewServer(
		grpc.Creds(peertracker.NewCredentials()),
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
	)

	workload_pb.RegisterSpiffeWorkloadAPIServer(server, e.workloadAPIServer)
	secret_v3.RegisterSecretDiscoveryServiceServer(server, e.sdsv3Server)
	grpc_health_v1.RegisterHealthServer(server, e.healthServer)

	tcpServer := e.createTCPServer(unaryInterceptor, streamInterceptor)
	workload_pb.RegisterSpiffeWorkloadAPIServer(tcpServer, e.workloadAPIServer)

	tasks := []func(context.Context) error{
		func(ctx context.Context) error {
			return e.runTCPServer(ctx, tcpServer)
		},
		func(ctx context.Context) error {
			return e.runLocalAccess(ctx, server)
		},
	}
	err := util.RunTasks(ctx, tasks...)
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	return err
}

func (e *Endpoints) triggerListeningHook() {
	if e.hooks.listening != nil {
		e.hooks.listening <- struct{}{}
	}
}

func (e *Endpoints) runLocalAccess(ctx context.Context, server *grpc.Server) error {
	l, err := e.createListener()
	if err != nil {
		return err
	}
	defer l.Close()

	// Update the listening address with the actual address.
	// If a TCP address was specified with port 0, this will
	// update the address with the actual port that is used
	// to listen.
	e.addr = l.Addr()
	e.log.WithFields(logrus.Fields{
		telemetry.Network: e.addr.Network(),
		telemetry.Address: e.addr,
	}).Info("Starting Workload and SDS APIs")
	e.triggerListeningHook()
	errChan := make(chan error)
	go func() { errChan <- server.Serve(l) }()

	select {
	case err = <-errChan:
		return err
	case <-ctx.Done():
		e.log.Info("Stopping Workload and SDS APIs")
		server.Stop()
		<-errChan
		e.log.Info("Workload and SDS APIs APIs have stopped")
		return nil
	}
}

func (e *Endpoints) createTCPServer(unaryInterceptor grpc.UnaryServerInterceptor, streamInterceptor grpc.StreamServerInterceptor) *grpc.Server {
	return grpc.NewServer(
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionAge: defaultMaxConnectionAge,
		}),
	)
}

// runTCPServer will start the server and block until it exits or we are dying.
func (e *Endpoints) runTCPServer(ctx context.Context, server *grpc.Server) error {
	l, err := net.Listen("tcp", "127.0.0.1:8082")
	if err != nil {
		return err
	}
	defer l.Close()
	log := e.log.WithFields(logrus.Fields{
		telemetry.Network: l.Addr().Network(),
		telemetry.Address: l.Addr().String(),
	})

	// Skip use of tomb here so we don't pollute a clean shutdown with errors
	log.Info("Starting Agent APIs")
	errChan := make(chan error)
	go func() { errChan <- server.Serve(l) }()

	select {
	case err = <-errChan:
		log.WithError(err).Error("Agent APIs stopped prematurely")
		return err
	case <-ctx.Done():
		log.Info("Stopping Agent APIs")
		server.Stop()
		<-errChan
		log.Info("Agent APIs have stopped")
		return nil
	}
}
