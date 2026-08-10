package coreplugin

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() {
	insertDirectiveBefore(pluginName, "cache")
	plugin.Register(pluginName, setup)
}

func setup(c *caddy.Controller) error {
	c.Next()
	if c.NextArg() {
		return plugin.Error(pluginName, c.ArgErr())
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Handler{Next: next}
	})
	return nil
}

func insertDirectiveBefore(name, before string) {
	for _, directive := range dnsserver.Directives {
		if directive == name {
			return
		}
	}
	for i, directive := range dnsserver.Directives {
		if directive == before {
			next := append([]string{}, dnsserver.Directives[:i]...)
			next = append(next, name)
			next = append(next, dnsserver.Directives[i:]...)
			dnsserver.Directives = next
			return
		}
	}
	dnsserver.Directives = append(dnsserver.Directives, name)
}
