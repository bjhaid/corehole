package coredns

import (
	"context"
	"errors"
	"sync"

	"github.com/bjhaid/corehole/internal/config"
	_ "github.com/bjhaid/corehole/internal/coreplugin"
	"github.com/coredns/caddy"
	_ "github.com/coredns/coredns/core/dnsserver"
	_ "github.com/coredns/coredns/plugin/cache"
	_ "github.com/coredns/coredns/plugin/errors"
	_ "github.com/coredns/coredns/plugin/forward"
	_ "github.com/coredns/coredns/plugin/log"
	_ "github.com/coredns/coredns/plugin/metadata"
	_ "github.com/coredns/coredns/plugin/rewrite"
)

type Server struct {
	mu       sync.Mutex
	instance *caddy.Instance
}

func Start(_ context.Context, cfg config.Config) (*Server, error) {
	caddy.AppName = "corehole"
	caddy.AppVersion = "dev"

	instance, err := caddy.Start(caddyfileInput(cfg))
	if err != nil {
		return nil, err
	}
	return &Server{instance: instance}, nil
}

func (s *Server) Reload(ctx context.Context, cfg config.Config) error {
	if s == nil {
		return errors.New("coredns server is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.instance == nil {
		return errors.New("coredns server is not running")
	}

	instance, err := s.instance.Restart(caddyfileInput(cfg))
	if err != nil {
		return err
	}
	s.instance = instance
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.instance == nil {
		return nil
	}
	done := make(chan error, 1)
	go func() {
		done <- s.instance.Stop()
	}()

	select {
	case err := <-done:
		if err == nil {
			s.instance = nil
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func caddyfileInput(cfg config.Config) caddy.CaddyfileInput {
	return caddy.CaddyfileInput{
		Contents:       []byte(Corefile(cfg)),
		Filepath:       "generated Corefile",
		ServerTypeName: "dns",
	}
}
