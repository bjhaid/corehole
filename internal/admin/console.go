package admin

import (
	"embed"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

//go:embed static
var consoleFiles embed.FS

var consoleStaticFS = mustSubFS(consoleFiles, "static")
var consoleTemplate = template.Must(template.ParseFS(
	consoleFiles,
	"static/index.html",
	"static/pages/*.html",
	"static/templates/*.html",
))

type consolePage struct {
	Name     string
	Path     string
	Title    string
	Template string
	Script   string
}

type consoleNavItem struct {
	Name    string
	Path    string
	Label   string
	Current bool
}

type consoleViewData struct {
	Page          consolePage
	Nav           []consoleNavItem
	Authenticated bool
	AuthMode      string
}

var consolePages = []consolePage{
	{Name: "dashboard", Path: "/admin/dashboard", Title: "Dashboard", Template: "page.dashboard", Script: "dashboard.js"},
	{Name: "queries", Path: "/admin/queries", Title: "Queries", Template: "page.queries", Script: "queries.js"},
	{Name: "analytics", Path: "/admin/analytics", Title: "Analytics", Template: "page.analytics", Script: "analytics.js"},
	{Name: "blocklists", Path: "/admin/blocklists", Title: "Blocklists", Template: "page.blocklists", Script: "blocklists.js"},
	{Name: "rules", Path: "/admin/rules", Title: "Rules", Template: "page.rules", Script: "rules.js"},
	{Name: "clients-groups", Path: "/admin/clients-groups", Title: "Clients / Groups", Template: "page.clients-groups", Script: "clients-groups.js"},
	{Name: "custom-dns", Path: "/admin/custom-dns", Title: "Custom DNS", Template: "page.custom-dns", Script: "custom-dns.js"},
	{Name: "settings", Path: "/admin/settings", Title: "Settings / API Keys", Template: "page.settings", Script: "settings.js"},
}

func (s *Server) handleConsole(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/assets/") {
		s.handleConsoleAsset(w, r)
		return
	}
	if r.Method != http.MethodGet {
		if r.URL.Path == "/" || r.URL.Path == "/admin" || r.URL.Path == "/admin/login" || r.URL.Path == "/admin/setup" {
			methodNotAllowed(w)
			return
		}
		if _, ok := consolePageForPath(r.URL.Path); ok {
			methodNotAllowed(w)
			return
		}
	}

	setup, err := s.userStore.IsSetup(r.Context())
	if err != nil {
		http.Error(w, "console unavailable", http.StatusInternalServerError)
		return
	}
	authenticated := s.authenticatedBySession(r)

	if r.URL.Path == "/" || r.URL.Path == "/admin" {
		http.Redirect(w, r, consoleDefaultRedirect(setup, authenticated), http.StatusFound)
		return
	}
	if r.URL.Path == "/admin/setup" {
		if setup {
			http.Redirect(w, r, consoleDefaultRedirect(setup, authenticated), http.StatusFound)
			return
		}
		s.renderConsole(w, consoleViewData{Page: consolePage{Name: "setup", Path: "/admin/setup", Title: "Setup", Script: "auth.js"}, AuthMode: "setup"})
		return
	}
	if r.URL.Path == "/admin/login" {
		if !setup {
			http.Redirect(w, r, "/admin/setup", http.StatusFound)
			return
		}
		if authenticated {
			http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
			return
		}
		s.renderConsole(w, consoleViewData{Page: consolePage{Name: "login", Path: "/admin/login", Title: "Login", Script: "auth.js"}, AuthMode: "login"})
		return
	}
	page, ok := consolePageForPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !setup {
		http.Redirect(w, r, "/admin/setup", http.StatusFound)
		return
	}
	if !authenticated {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}
	s.renderConsole(w, consoleDataForPage(page, true))
}

func (s *Server) renderConsole(w http.ResponseWriter, data consoleViewData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	if err := consoleTemplate.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, "console template render failed", http.StatusInternalServerError)
	}
}

func (s *Server) handleConsoleAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/assets/")
	if name == "" || name != path.Clean(name) || !fs.ValidPath(name) {
		http.NotFound(w, r)
		return
	}

	info, err := fs.Stat(consoleStaticFS, name)
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}

	switch path.Ext(name) {
	case ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	default:
		if contentType := mime.TypeByExtension(path.Ext(name)); contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
	}
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFileFS(w, r, consoleStaticFS, name)
}

func consolePageForPath(requestPath string) (consolePage, bool) {
	for _, page := range consolePages {
		if page.Path == requestPath {
			return page, true
		}
	}
	return consolePage{}, false
}

func consoleDefaultRedirect(setup bool, authenticated bool) string {
	if !setup {
		return "/admin/setup"
	}
	if authenticated {
		return "/admin/dashboard"
	}
	return "/admin/login"
}

func consoleDataForPage(page consolePage, authenticated bool) consoleViewData {
	nav := make([]consoleNavItem, 0, len(consolePages))
	for _, item := range consolePages {
		nav = append(nav, consoleNavItem{
			Name:    item.Name,
			Path:    item.Path,
			Label:   item.Title,
			Current: item.Name == page.Name,
		})
	}
	return consoleViewData{Page: page, Nav: nav, Authenticated: authenticated}
}

func mustSubFS(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(err)
	}
	return sub
}
