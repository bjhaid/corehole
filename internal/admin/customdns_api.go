package admin

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/bjhaid/corehole/internal/localdns"
)

type LocalDNSStore interface {
	Create(ctx context.Context, input localdns.RecordInput) (localdns.Record, error)
	List(ctx context.Context) ([]localdns.Record, error)
	Get(ctx context.Context, id int64) (localdns.Record, error)
	Update(ctx context.Context, id int64, input localdns.RecordInput) (localdns.Record, error)
	Delete(ctx context.Context, id int64) error
}

type LocalDNSReloader interface {
	ReloadLocalDNS(ctx context.Context) error
}

func WithLocalDNSStore(store LocalDNSStore) Option {
	return func(s *Server) {
		if store != nil {
			s.localDNS = store
		}
	}
}

func WithLocalDNSReloader(reloader LocalDNSReloader) Option {
	return func(s *Server) {
		if reloader != nil {
			s.localDNSReload = reloader
		}
	}
}

type customDNSRecordsResponse struct {
	Records []localdns.Record `json:"records"`
}

func (s *Server) handleCustomDNSRecords(w http.ResponseWriter, r *http.Request) {
	store, ok := s.localDNSStore(w)
	if !ok {
		return
	}

	switch r.Method {
	case http.MethodGet:
		records, err := store.List(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "custom_dns_list_failed")
			return
		}
		writeJSON(w, http.StatusOK, customDNSRecordsResponse{Records: records})
	case http.MethodPost:
		var req localdns.RecordInput
		if !decodeJSON(w, r, &req) {
			return
		}
		record, err := store.Create(r.Context(), req)
		if err != nil {
			if errors.Is(err, localdns.ErrInvalidRecord) {
				writeError(w, http.StatusBadRequest, "invalid_custom_dns_record")
				return
			}
			writeError(w, http.StatusInternalServerError, "custom_dns_create_failed")
			return
		}
		if !s.reloadLocalDNS(w, r) {
			return
		}
		writeJSON(w, http.StatusCreated, record)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleCustomDNSRecord(w http.ResponseWriter, r *http.Request) {
	store, ok := s.localDNSStore(w)
	if !ok {
		return
	}

	id, ok := customDNSRecordID(w, r)
	if !ok {
		return
	}

	switch r.Method {
	case http.MethodGet:
		record, err := store.Get(r.Context(), id)
		if err != nil {
			handleCustomDNSError(w, err, "custom_dns_get_failed")
			return
		}
		writeJSON(w, http.StatusOK, record)
	case http.MethodPut:
		var req localdns.RecordInput
		if !decodeJSON(w, r, &req) {
			return
		}
		record, err := store.Update(r.Context(), id, req)
		if err != nil {
			handleCustomDNSError(w, err, "custom_dns_update_failed")
			return
		}
		if !s.reloadLocalDNS(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, record)
	case http.MethodDelete:
		if err := store.Delete(r.Context(), id); err != nil {
			handleCustomDNSError(w, err, "custom_dns_delete_failed")
			return
		}
		if !s.reloadLocalDNS(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) reloadLocalDNS(w http.ResponseWriter, r *http.Request) bool {
	if s.localDNSReload == nil {
		return true
	}
	if err := s.localDNSReload.ReloadLocalDNS(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "custom_dns_reload_failed")
		return false
	}
	return true
}

func (s *Server) localDNSStore(w http.ResponseWriter) (LocalDNSStore, bool) {
	if s.localDNS == nil {
		writeError(w, http.StatusServiceUnavailable, "custom_dns_unavailable")
		return nil, false
	}
	return s.localDNS, true
}

func customDNSRecordID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	raw := strings.TrimPrefix(r.URL.Path, "/api/custom-dns/records/")
	if raw == "" || strings.Contains(raw, "/") {
		writeError(w, http.StatusNotFound, "custom_dns_record_not_found")
		return 0, false
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusNotFound, "custom_dns_record_not_found")
		return 0, false
	}
	return id, true
}

func handleCustomDNSError(w http.ResponseWriter, err error, fallback string) {
	switch {
	case errors.Is(err, localdns.ErrNotFound):
		writeError(w, http.StatusNotFound, "custom_dns_record_not_found")
	case errors.Is(err, localdns.ErrInvalidRecord):
		writeError(w, http.StatusBadRequest, "invalid_custom_dns_record")
	default:
		writeError(w, http.StatusInternalServerError, fallback)
	}
}
