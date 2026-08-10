package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	apiKeyRawBytes     = 32
	apiKeySecretPrefix = "ch_"
	apiKeyPrefixLength = 12
	apiKeyLast4Length  = 4
	apiKeyHeaderName   = "X-Corehole-API-Key"
)

func (s *Server) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	if s.apiKeys == nil {
		writeError(w, http.StatusServiceUnavailable, "api_keys_unavailable")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleListAPIKeys(w, r)
	case http.MethodPost:
		s.handleCreateAPIKey(w, r)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleAPIKey(w http.ResponseWriter, r *http.Request) {
	if s.apiKeys == nil {
		writeError(w, http.StatusServiceUnavailable, "api_keys_unavailable")
		return
	}
	if r.Method != http.MethodDelete {
		methodNotAllowed(w)
		return
	}

	idText := strings.TrimPrefix(r.URL.Path, "/api/api-keys/")
	if idText == "" || strings.Contains(idText, "/") {
		writeError(w, http.StatusNotFound, "api_key_not_found")
		return
	}
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusNotFound, "api_key_not_found")
		return
	}

	err = s.apiKeys.RevokeAPIKey(r.Context(), id, time.Now().UTC())
	if errors.Is(err, ErrAPIKeyNotFound) {
		writeError(w, http.StatusNotFound, "api_key_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "api_key_revoke_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.apiKeys.ListAPIKeys(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "api_key_list_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string][]APIKey{"api_keys": keys})
}

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req apiKeyCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "name_required")
		return
	}

	rawKey, err := generateAPIKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "api_key_generation_failed")
		return
	}

	now := time.Now().UTC()
	key, err := s.apiKeys.CreateAPIKey(
		r.Context(),
		name,
		hashAPIKey(rawKey),
		apiKeyPrefix(rawKey),
		apiKeyLast4(rawKey),
		now,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "api_key_create_failed")
		return
	}

	writeJSON(w, http.StatusCreated, apiKeyCreateResponse{
		APIKey: key,
		Key:    rawKey,
	})
}

func (s *Server) authenticatedByAPIKey(r *http.Request) bool {
	if s.apiKeys == nil {
		return false
	}

	rawKey := apiKeyFromRequest(r)
	if rawKey == "" {
		return false
	}

	now := time.Now().UTC()
	key, err := s.apiKeys.FindValidAPIKeyByHash(r.Context(), hashAPIKey(rawKey))
	if err != nil {
		return false
	}
	_ = s.apiKeys.MarkAPIKeyUsed(r.Context(), key.ID, now)
	return true
}

func apiKeyFromRequest(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth != "" {
		parts := strings.Fields(auth)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return strings.TrimSpace(parts[1])
		}
	}
	return strings.TrimSpace(r.Header.Get(apiKeyHeaderName))
}

func generateAPIKey() (string, error) {
	keyBytes := make([]byte, apiKeyRawBytes)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", err
	}
	return apiKeySecretPrefix + base64.RawURLEncoding.EncodeToString(keyBytes), nil
}

func hashAPIKey(rawKey string) string {
	sum := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(sum[:])
}

func apiKeyPrefix(rawKey string) string {
	if len(rawKey) <= apiKeyPrefixLength {
		return rawKey
	}
	return rawKey[:apiKeyPrefixLength]
}

func apiKeyLast4(rawKey string) string {
	if len(rawKey) <= apiKeyLast4Length {
		return rawKey
	}
	return rawKey[len(rawKey)-apiKeyLast4Length:]
}

type apiKeyCreateRequest struct {
	Name string `json:"name"`
}

type apiKeyCreateResponse struct {
	APIKey APIKey `json:"api_key"`
	Key    string `json:"key"`
}
