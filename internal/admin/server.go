package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

const defaultSessionCookieName = "corehole_admin_session"

type Server struct {
	userStore      UserStore
	apiKeys        APIKeyStore
	sessions       SessionStore
	hasher         PasswordHasher
	cookieName     string
	sessionTTL     time.Duration
	secureCookie   bool
	auditReader    AuditReader
	configSource   ConfigSource
	localDNS       LocalDNSStore
	filterService  FilterService
	filterReloader FilterReloader
	mux            *http.ServeMux
}

type Option func(*Server)

func WithPasswordHasher(hasher PasswordHasher) Option {
	return func(s *Server) {
		if hasher != nil {
			s.hasher = hasher
		}
	}
}

func WithSessionStore(store SessionStore) Option {
	return func(s *Server) {
		if store != nil {
			s.sessions = store
		}
	}
}

func WithAPIKeyStore(store APIKeyStore) Option {
	return func(s *Server) {
		if store != nil {
			s.apiKeys = store
		}
	}
}

func WithCookieName(name string) Option {
	return func(s *Server) {
		if name != "" {
			s.cookieName = name
		}
	}
}

func WithSessionTTL(ttl time.Duration) Option {
	return func(s *Server) {
		if ttl > 0 {
			s.sessionTTL = ttl
		}
	}
}

func WithSecureCookie(secure bool) Option {
	return func(s *Server) {
		s.secureCookie = secure
	}
}

func NewServer(userStore UserStore, opts ...Option) *Server {
	if userStore == nil {
		userStore = NewMemoryUserStore()
	}

	s := &Server{
		userStore:    userStore,
		sessions:     NewMemorySessionStore(),
		hasher:       NewArgon2idHasher(Argon2idParams{}),
		cookieName:   defaultSessionCookieName,
		sessionTTL:   24 * time.Hour,
		secureCookie: true,
		mux:          http.NewServeMux(),
	}
	if store, ok := userStore.(APIKeyStore); ok {
		s.apiKeys = store
	}
	for _, opt := range opts {
		opt(s)
	}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("/", s.handleConsole)
	s.mux.HandleFunc("/api/status", s.handleStatus)
	s.mux.HandleFunc("/api/setup", s.handleSetup)
	s.mux.HandleFunc("/api/login", s.handleLogin)
	s.mux.HandleFunc("/api/logout", s.requireSession(s.handleLogout))
	s.mux.HandleFunc("/api/api-keys", s.requireSession(s.handleAPIKeys))
	s.mux.HandleFunc("/api/api-keys/", s.requireSession(s.handleAPIKey))
	s.mux.HandleFunc("/api/dashboard", s.requireSession(s.handleDashboard))
	s.mux.HandleFunc("/api/queries", s.requireSession(s.handleQueries))
	s.mux.HandleFunc("/api/analytics/queries", s.requireSession(s.handleAnalyticsQueries))
	s.mux.HandleFunc("/api/analytics/summary", s.requireSession(s.handleAnalyticsSummary))
	s.mux.HandleFunc("/api/analytics/settings", s.requireSession(s.handleAnalyticsSettings))
	s.mux.HandleFunc("/api/analytics/cleanup", s.requireSession(s.handleAnalyticsCleanup))
	s.mux.HandleFunc("/api/config", s.requireSession(s.handleConfig))
	s.mux.HandleFunc("/api/localdns/records", s.requireSession(s.handleLocalDNSRecords))
	s.mux.HandleFunc("/api/localdns/records/", s.requireSession(s.handleLocalDNSRecord))
	s.mux.HandleFunc("/api/filter/lists", s.requireSession(s.handleFilterLists))
	s.mux.HandleFunc("/api/filter/lists/", s.requireSession(s.handleFilterList))
	s.mux.HandleFunc("/api/filter/list-entries/", s.requireSession(s.handleFilterListEntry))
	s.mux.HandleFunc("/api/filter/rules", s.requireSession(s.handleFilterRules))
	s.mux.HandleFunc("/api/filter/rules/", s.requireSession(s.handleFilterRule))
	s.mux.HandleFunc("/api/filter/clients/suggestions", s.requireSession(s.handleFilterClientSuggestions))
	s.mux.HandleFunc("/api/filter/clients", s.requireSession(s.handleFilterClients))
	s.mux.HandleFunc("/api/filter/clients/", s.requireSession(s.handleFilterClient))
	s.mux.HandleFunc("/api/filter/groups", s.requireSession(s.handleFilterGroups))
	s.mux.HandleFunc("/api/filter/groups/", s.requireSession(s.handleFilterGroup))
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	setup, err := s.userStore.IsSetup(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "status_unavailable")
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{
		"setup_required": !setup,
		"authenticated":  s.authenticated(r),
	})
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req passwordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "password_required")
		return
	}

	setup, err := s.userStore.IsSetup(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "setup_unavailable")
		return
	}
	if setup {
		writeError(w, http.StatusConflict, "already_setup")
		return
	}

	passwordHash, err := s.hasher.Hash([]byte(req.Password))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "password_hash_failed")
		return
	}
	if err := s.userStore.CreateAdmin(r.Context(), passwordHash); err != nil {
		if errors.Is(err, ErrAlreadySetup) {
			writeError(w, http.StatusConflict, "already_setup")
			return
		}
		writeError(w, http.StatusInternalServerError, "setup_failed")
		return
	}

	if err := s.setSessionCookie(w); err != nil {
		writeError(w, http.StatusInternalServerError, "session_failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]bool{"ok": true})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req passwordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "password_required")
		return
	}

	passwordHash, err := s.userStore.AdminPasswordHash(r.Context())
	if err != nil {
		if errors.Is(err, ErrNotSetup) {
			writeError(w, http.StatusConflict, "setup_required")
			return
		}
		writeError(w, http.StatusInternalServerError, "login_unavailable")
		return
	}

	ok, err := s.hasher.Compare(passwordHash, []byte(req.Password))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "password_verify_failed")
		return
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}

	if err := s.setSessionCookie(w); err != nil {
		writeError(w, http.StatusInternalServerError, "session_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	cookie, err := r.Cookie(s.cookieName)
	if err == nil {
		s.sessions.Delete(cookie.Value)
	}
	http.SetCookie(w, s.expiredCookie())
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authenticated(r) {
			writeError(w, http.StatusUnauthorized, "authentication_required")
			return
		}
		next(w, r)
	}
}

func (s *Server) authenticated(r *http.Request) bool {
	if s.authenticatedBySession(r) {
		return true
	}
	return s.authenticatedByAPIKey(r)
}

func (s *Server) authenticatedBySession(r *http.Request) bool {
	cookie, err := r.Cookie(s.cookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	return s.sessions.Valid(cookie.Value, time.Now())
}

func (s *Server) setSessionCookie(w http.ResponseWriter) error {
	token, err := s.sessions.Create(time.Now(), s.sessionTTL)
	if err != nil {
		return err
	}
	http.SetCookie(w, s.sessionCookie(token))
	return nil
}

func (s *Server) sessionCookie(token string) *http.Cookie {
	return &http.Cookie{
		Name:     s.cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookie,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.sessionTTL.Seconds()),
		Expires:  time.Now().Add(s.sessionTTL),
	}
}

func (s *Server) expiredCookie() *http.Cookie {
	return &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookie,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	}
}

type passwordRequest struct {
	Password string `json:"password"`
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
