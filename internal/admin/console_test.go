package admin

import (
	"bytes"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func consoleResponseBody(t *testing.T, server http.Handler, path string, contentType string) []byte {
	t.Helper()

	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	server.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("%s status code = %d, want %d", path, res.Code, http.StatusOK)
	}
	if got := res.Header().Get("Content-Type"); got != contentType {
		t.Fatalf("%s content-type = %q, want %s", path, got, contentType)
	}
	return res.Body.Bytes()
}

func consoleAssetBundle(t *testing.T, server http.Handler) []byte {
	t.Helper()

	paths := []struct {
		path        string
		contentType string
	}{
		{"/admin/dashboard", "text/html; charset=utf-8"},
		{"/admin/settings", "text/html; charset=utf-8"},
		{"/assets/css/app.css", "text/css; charset=utf-8"},
		{"/assets/css/base.css", "text/css; charset=utf-8"},
		{"/assets/css/layout.css", "text/css; charset=utf-8"},
		{"/assets/css/components.css", "text/css; charset=utf-8"},
		{"/assets/css/pages.css", "text/css; charset=utf-8"},
		{"/assets/css/responsive.css", "text/css; charset=utf-8"},
		{"/assets/assets/corehole-logo.svg", "image/svg+xml"},
		{"/assets/js/admin.js", "text/javascript; charset=utf-8"},
		{"/assets/js/lib/api.js", "text/javascript; charset=utf-8"},
		{"/assets/js/lib/dom.js", "text/javascript; charset=utf-8"},
		{"/assets/js/lib/elements.js", "text/javascript; charset=utf-8"},
		{"/assets/js/lib/format.js", "text/javascript; charset=utf-8"},
		{"/assets/js/pages/dashboard.js", "text/javascript; charset=utf-8"},
		{"/assets/js/pages/queries.js", "text/javascript; charset=utf-8"},
		{"/assets/js/pages/settings.js", "text/javascript; charset=utf-8"},
	}

	var body []byte
	for _, asset := range paths {
		body = append(body, consoleResponseBody(t, server, asset.path, asset.contentType)...)
		body = append(body, '\n')
	}
	return body
}

func TestConsoleDashboardServesBackendRenderedPage(t *testing.T) {
	server := newTestServer()
	body := consoleResponseBody(t, server, "/admin/dashboard", "text/html; charset=utf-8")

	for _, want := range [][]byte{
		[]byte("<h1>Corehole</h1>"),
		[]byte(`<link rel="icon" type="image/svg+xml" href="/assets/assets/corehole-logo.svg">`),
		[]byte(`<img class="brand-mark" src="/assets/assets/corehole-logo.svg"`),
		[]byte(`<link rel="stylesheet" href="/assets/css/app.css">`),
		[]byte(`window.__COREHOLE_PAGE__ = "dashboard";`),
		[]byte(`<script type="module" src="/assets/js/pages/dashboard.js"></script>`),
		[]byte(`class="side-nav" aria-label="Admin sections"`),
		[]byte(`id="nav-dashboard" class="nav-link" href="/admin/dashboard" aria-current="page"`),
		[]byte(`id="nav-queries" class="nav-link" href="/admin/queries"`),
		[]byte(`id="nav-analytics" class="nav-link" href="/admin/analytics"`),
		[]byte(`id="nav-blocklists" class="nav-link" href="/admin/blocklists"`),
		[]byte(`id="nav-rules" class="nav-link" href="/admin/rules"`),
		[]byte(`id="nav-clients-groups" class="nav-link" href="/admin/clients-groups"`),
		[]byte(`id="nav-local-dns" class="nav-link" href="/admin/local-dns"`),
		[]byte(`id="nav-settings" class="nav-link" href="/admin/settings"`),
		[]byte(`id="panel-dashboard" class="page-panel page-stack" data-page="dashboard"`),
		[]byte("Total queries"),
		[]byte("All-time DNS requests"),
		[]byte("All-time filtered DNS requests"),
		[]byte("All-time resolved DNS requests"),
		[]byte("All-time audit sink backpressure"),
		[]byte(`id="template-query-row"`),
	} {
		if !bytes.Contains(body, want) {
			t.Fatalf("console body missing %q", want)
		}
	}
	for _, notWant := range [][]byte{
		[]byte(`data-route=`),
		[]byte(`id="panel-query-log"`),
		[]byte(`id="panel-analytics"`),
		[]byte(`id="panel-blocklists"`),
		[]byte(`id="panel-rules"`),
		[]byte(`id="panel-clients-groups"`),
		[]byte(`id="panel-local-dns"`),
		[]byte(`id="panel-settings"`),
		[]byte("Recent queries"),
		[]byte("Recent time buckets"),
		[]byte(`id="query-filter-reason"`),
	} {
		if bytes.Contains(body, notWant) {
			t.Fatalf("console body includes obsolete content %q", notWant)
		}
	}
}

func TestConsoleRootAndAdminRedirectToDashboard(t *testing.T) {
	server := newTestServer()

	for _, path := range []string{"/", "/admin"} {
		t.Run(path, func(t *testing.T) {
			res := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			server.ServeHTTP(res, req)

			if res.Code != http.StatusFound {
				t.Fatalf("status code = %d, want %d", res.Code, http.StatusFound)
			}
			if got := res.Header().Get("Location"); got != "/admin/dashboard" {
				t.Fatalf("location = %q, want /admin/dashboard", got)
			}
		})
	}
}

func TestConsoleAdminRoutesServeDistinctBackendPages(t *testing.T) {
	server := newTestServer()

	for _, tt := range []struct {
		path       string
		page       string
		script     string
		contains   []byte
		notContain []byte
	}{
		{"/admin/dashboard", "dashboard", "dashboard.js", []byte("All-time DNS requests"), []byte(`id="panel-query-log"`)},
		{"/admin/queries", "queries", "queries.js", []byte("Recent query log"), []byte(`id="panel-dashboard"`)},
		{"/admin/analytics", "analytics", "analytics.js", []byte("Analytics / Privacy"), []byte(`id="panel-dashboard"`)},
		{"/admin/blocklists", "blocklists", "blocklists.js", []byte("Blocklists / adlists"), []byte(`id="panel-dashboard"`)},
		{"/admin/rules", "rules", "rules.js", []byte("<h3>Rules</h3>"), []byte(`id="panel-dashboard"`)},
		{"/admin/clients-groups", "clients-groups", "clients-groups.js", []byte("<h3>Clients</h3>"), []byte(`id="panel-dashboard"`)},
		{"/admin/local-dns", "local-dns", "local-dns.js", []byte("Local DNS"), []byte(`id="panel-dashboard"`)},
		{"/admin/settings", "settings", "settings.js", []byte("Settings / API Keys"), []byte(`id="panel-dashboard"`)},
	} {
		t.Run(tt.path, func(t *testing.T) {
			body := consoleResponseBody(t, server, tt.path, "text/html; charset=utf-8")
			if !bytes.Contains(body, []byte(`window.__COREHOLE_PAGE__ = "`+tt.page+`";`)) {
				t.Fatalf("%s missing page bootstrap for %s", tt.path, tt.page)
			}
			if !bytes.Contains(body, []byte(`/assets/js/pages/`+tt.script)) {
				t.Fatalf("%s missing script %s", tt.path, tt.script)
			}
			if !bytes.Contains(body, tt.contains) {
				t.Fatalf("%s missing page content %q", tt.path, tt.contains)
			}
			if bytes.Contains(body, tt.notContain) {
				t.Fatalf("%s includes content from another page %q", tt.path, tt.notContain)
			}
			if bytes.Contains(body, []byte(`data-route=`)) {
				t.Fatalf("%s includes client-side route markers", tt.path)
			}
		})
	}
}

func TestConsoleEmbeddedAssetsAvailable(t *testing.T) {
	for _, name := range []string{
		"static/index.html",
		"static/pages/dashboard.html",
		"static/pages/queries.html",
		"static/pages/analytics.html",
		"static/pages/blocklists.html",
		"static/pages/rules.html",
		"static/pages/clients-groups.html",
		"static/pages/local-dns.html",
		"static/pages/settings.html",
		"static/templates/rows.html",
		"static/assets/corehole-logo.svg",
		"static/css/app.css",
		"static/css/base.css",
		"static/css/layout.css",
		"static/css/components.css",
		"static/css/pages.css",
		"static/css/responsive.css",
		"static/js/admin.js",
		"static/js/lib/api.js",
		"static/js/lib/analytics-summary.js",
		"static/js/lib/dom.js",
		"static/js/lib/elements.js",
		"static/js/lib/filter-ui.js",
		"static/js/lib/format.js",
		"static/js/lib/forms.js",
		"static/js/lib/upstreams.js",
		"static/js/pages/dashboard.js",
		"static/js/pages/queries.js",
		"static/js/pages/analytics.js",
		"static/js/pages/blocklists.js",
		"static/js/pages/rules.js",
		"static/js/pages/clients-groups.js",
		"static/js/pages/local-dns.js",
		"static/js/pages/settings.js",
	} {
		t.Run(name, func(t *testing.T) {
			body, err := fs.ReadFile(consoleFiles, name)
			if err != nil {
				t.Fatalf("embedded asset %s unavailable: %v", name, err)
			}
			if len(body) == 0 {
				t.Fatalf("embedded asset %s is empty", name)
			}
		})
	}
}

func TestConsoleNestedAssetRoutesServeEmbeddedAssets(t *testing.T) {
	server := newTestServer()

	for _, tt := range []struct {
		path        string
		contentType string
		contains    []byte
	}{
		{
			path:        "/assets/css/app.css",
			contentType: "text/css; charset=utf-8",
			contains:    []byte(`@import url("./base.css");`),
		},
		{
			path:        "/assets/css/components.css",
			contentType: "text/css; charset=utf-8",
			contains:    []byte(`.upstream-form {`),
		},
		{
			path:        "/assets/js/pages/dashboard.js",
			contentType: "text/javascript; charset=utf-8",
			contains:    []byte(`initAdminPage({`),
		},
		{
			path:        "/assets/assets/corehole-logo.svg",
			contentType: "image/svg+xml",
			contains:    []byte(`<title id="title">Corehole logo</title>`),
		},
	} {
		t.Run(tt.path, func(t *testing.T) {
			res := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			server.ServeHTTP(res, req)

			if res.Code != http.StatusOK {
				t.Fatalf("status code = %d, want %d", res.Code, http.StatusOK)
			}
			if got := res.Header().Get("Content-Type"); got != tt.contentType {
				t.Fatalf("content-type = %q, want %s", got, tt.contentType)
			}
			if got := res.Header().Get("Cache-Control"); got != "no-cache" {
				t.Fatalf("cache-control = %q, want no-cache", got)
			}
			if !bytes.Contains(res.Body.Bytes(), tt.contains) {
				t.Fatalf("asset body missing %q", tt.contains)
			}
		})
	}
}

func TestConsoleAssetRoutesRejectInvalidNestedPaths(t *testing.T) {
	server := newTestServer()

	for _, path := range []string{
		"/assets/",
		"/assets/css",
		"/assets/missing.js",
		"/assets/js/../admin.js",
	} {
		t.Run(path, func(t *testing.T) {
			res := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			server.ServeHTTP(res, req)

			if res.Code == http.StatusOK {
				t.Fatalf("status code = %d, want non-OK rejection", res.Code)
			}
		})
	}
}

func TestConsoleQueryLogTypeActionAndResponseFiltersAreSelects(t *testing.T) {
	server := newTestServer()
	body := string(consoleResponseBody(t, server, "/admin/queries", "text/html; charset=utf-8"))

	if strings.Contains(body, `<input id="query-filter-type"`) {
		t.Fatalf("console body includes type filter input")
	}
	if strings.Contains(body, `<input id="query-filter-action"`) {
		t.Fatalf("console body includes action filter input")
	}
	if strings.Contains(body, `<input id="query-filter-response"`) {
		t.Fatalf("console body includes response filter input")
	}

	assertSelectOptions(t, body, "query-filter-type", []string{
		"",
		"A",
		"AAAA",
		"CNAME",
		"MX",
		"TXT",
		"PTR",
		"NS",
		"SOA",
		"SRV",
		"HTTPS",
	})
	assertSelectOptions(t, body, "query-filter-action", []string{
		"",
		"allow",
		"block",
		"error",
	})
	assertSelectOptions(t, body, "query-filter-response", []string{
		"",
		"NOERROR",
		"NXDOMAIN",
		"REFUSED",
		"SERVFAIL",
		"FORMERR",
		"NOTIMP",
		"0.0.0.0",
		"::",
	})
}

func TestConsoleQueryLogColumnSettingsExposeDiagnosticColumns(t *testing.T) {
	server := newTestServer()
	body := string(consoleResponseBody(t, server, "/admin/queries", "text/html; charset=utf-8"))
	assets := string(consoleAssetBundle(t, server))

	for _, want := range []string{
		`id="query-column-toggle"`,
		`id="query-column-panel"`,
		`data-column="upstream"`,
		`data-query-sort="upstream_resolver"`,
		`data-column="cache"`,
		`data-query-sort="cache_status"`,
		`data-column="forward_duration"`,
		`data-query-sort="forward_duration_ms"`,
		`data-column="retries"`,
		`data-query-sort="retry_count"`,
		`data-column="forward_error"`,
		`data-query-sort="forward_error"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("console body missing query log column setting %q", want)
		}
	}
	for _, want := range []string{
		`corehole.queryLog.visibleColumns`,
		`{key: "upstream", label: "Upstream", defaultVisible: false}`,
		`{key: "cache", label: "Cache", defaultVisible: false}`,
		`{key: "forward_duration", label: "Forward ms", defaultVisible: false}`,
		`{key: "retries", label: "Retries", defaultVisible: false}`,
		`{key: "forward_error", label: "Upstream error", defaultVisible: false}`,
	} {
		if !strings.Contains(assets, want) {
			t.Fatalf("console assets missing query log column setting %q", want)
		}
	}
}

func TestConsoleUpstreamResolverLayoutUsesResponsiveConstraints(t *testing.T) {
	server := newTestServer()
	body := string(consoleAssetBundle(t, server))

	for _, want := range []string{
		`.upstream-form {`,
		`grid-template-columns: repeat(auto-fit, minmax(min(100%, 150px), 1fr));`,
		`.upstream-field-wide,`,
		`.upstream-actions {`,
		`grid-column: span 2;`,
		`.upstream-actions button {`,
		`flex: 1 0 120px;`,
		`.upstream-table {`,
		`min-width: 880px;`,
		`.upstream-table th:last-child,`,
		`.upstream-table .table-actions {`,
		`flex-wrap: nowrap;`,
		`<div class="upstream-field-wide">`,
		`class="checkbox-line upstream-enabled-field" for="upstream-enabled"`,
		`<div class="upstream-actions">`,
		`<table class="upstream-table">`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("console body missing upstream responsive layout %q", want)
		}
	}
}

func assertSelectOptions(t *testing.T, body, id string, values []string) {
	t.Helper()

	start := strings.Index(body, `<select id="`+id+`"`)
	if start == -1 {
		t.Fatalf("console body missing select %q", id)
	}
	end := strings.Index(body[start:], `</select>`)
	if end == -1 {
		t.Fatalf("console body missing closing select for %q", id)
	}
	selectBody := body[start : start+end]
	for _, value := range values {
		want := `<option value="` + value + `"`
		if !strings.Contains(selectBody, want) {
			t.Fatalf("select %q missing option value %q", id, value)
		}
	}
}

func TestConsoleUnknownPathReturnsNotFoundFromConsoleRoute(t *testing.T) {
	server := newTestServer()

	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	server.ServeHTTP(res, req)

	if res.Code != http.StatusNotFound {
		t.Fatalf("status code = %d, want %d", res.Code, http.StatusNotFound)
	}
}
