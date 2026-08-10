package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/bjhaid/corehole/internal/localdns"
)

func TestLocalDNSAPIRequiresSession(t *testing.T) {
	server := newTestServer(WithLocalDNSStore(newFakeLocalDNSStore()))

	for _, req := range []struct {
		method string
		path   string
		body   any
	}{
		{method: http.MethodGet, path: "/api/localdns/records"},
		{method: http.MethodPost, path: "/api/localdns/records", body: map[string]any{}},
		{method: http.MethodGet, path: "/api/localdns/records/1"},
		{method: http.MethodPut, path: "/api/localdns/records/1", body: map[string]any{}},
		{method: http.MethodDelete, path: "/api/localdns/records/1"},
	} {
		res := requestJSON(t, server, req.method, req.path, req.body, nil)
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s status code = %d, want %d", req.method, req.path, res.Code, http.StatusUnauthorized)
		}
	}
}

func TestLocalDNSAPICRUD(t *testing.T) {
	store := newFakeLocalDNSStore()
	server := newTestServer(WithLocalDNSStore(store))
	cookie := setupSession(t, server)

	create := requestJSON(t, server, http.MethodPost, "/api/localdns/records", map[string]any{
		"name":    "Host.Example.",
		"type":    "A",
		"value":   "192.0.2.55",
		"ttl":     120,
		"enabled": true,
		"comment": "office",
	}, cookie)
	if create.Code != http.StatusCreated {
		t.Fatalf("create status code = %d, want %d: %s", create.Code, http.StatusCreated, create.Body.String())
	}
	created := decodeResponse[localdns.Record](t, create)
	if created.ID == 0 || created.Name != "host.example" || created.Value != "192.0.2.55" || created.TTL != 120 || !created.Enabled {
		t.Fatalf("created record = %#v", created)
	}

	list := get(t, server, "/api/localdns/records", cookie)
	if list.Code != http.StatusOK {
		t.Fatalf("list status code = %d, want %d", list.Code, http.StatusOK)
	}
	listBody := decodeResponse[localDNSRecordsResponse](t, list)
	if len(listBody.Records) != 1 || listBody.Records[0].ID != created.ID {
		t.Fatalf("list body = %#v", listBody)
	}

	update := requestJSON(t, server, http.MethodPut, "/api/localdns/records/1", map[string]any{
		"name":    "alias.example",
		"type":    "CNAME",
		"value":   "host.example",
		"ttl":     300,
		"enabled": false,
	}, cookie)
	if update.Code != http.StatusOK {
		t.Fatalf("update status code = %d, want %d: %s", update.Code, http.StatusOK, update.Body.String())
	}
	updated := decodeResponse[localdns.Record](t, update)
	if updated.Type != localdns.TypeCNAME || updated.Value != "host.example" || updated.Enabled {
		t.Fatalf("updated record = %#v", updated)
	}

	getOne := get(t, server, "/api/localdns/records/1", cookie)
	if getOne.Code != http.StatusOK {
		t.Fatalf("get status code = %d, want %d", getOne.Code, http.StatusOK)
	}
	if got := decodeResponse[localdns.Record](t, getOne); got != updated {
		t.Fatalf("get record = %#v, want %#v", got, updated)
	}

	deleteRes := requestJSON(t, server, http.MethodDelete, "/api/localdns/records/1", nil, cookie)
	if deleteRes.Code != http.StatusNoContent {
		t.Fatalf("delete status code = %d, want %d", deleteRes.Code, http.StatusNoContent)
	}

	missing := get(t, server, "/api/localdns/records/1", cookie)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("get deleted status code = %d, want %d", missing.Code, http.StatusNotFound)
	}
}

func TestLocalDNSAPIRejectsInvalidRecord(t *testing.T) {
	server := newTestServer(WithLocalDNSStore(newFakeLocalDNSStore()))
	cookie := setupSession(t, server)

	res := requestJSON(t, server, http.MethodPost, "/api/localdns/records", map[string]any{
		"name":  "host.example",
		"type":  "A",
		"value": "2001:db8::1",
	}, cookie)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", res.Code, http.StatusBadRequest)
	}
}

func requestJSON(t *testing.T, server http.Handler, method string, path string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode request: %v", err)
		}
	}

	req := httptest.NewRequest(method, path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}

	res := httptest.NewRecorder()
	server.ServeHTTP(res, req)
	return res
}

type fakeLocalDNSStore struct {
	nextID  int64
	records map[int64]localdns.Record
}

func newFakeLocalDNSStore() *fakeLocalDNSStore {
	return &fakeLocalDNSStore{
		nextID:  1,
		records: make(map[int64]localdns.Record),
	}
}

func (s *fakeLocalDNSStore) Create(_ context.Context, input localdns.RecordInput) (localdns.Record, error) {
	record, err := localdns.NewRecord(input)
	if err != nil {
		return localdns.Record{}, err
	}
	record.ID = s.nextID
	s.nextID++
	record.CreatedAt = time.Unix(record.ID, 0).UTC()
	record.UpdatedAt = record.CreatedAt
	s.records[record.ID] = record
	return record, nil
}

func (s *fakeLocalDNSStore) List(context.Context) ([]localdns.Record, error) {
	records := make([]localdns.Record, 0, len(s.records))
	for _, record := range s.records {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].ID < records[j].ID
	})
	return records, nil
}

func (s *fakeLocalDNSStore) Get(_ context.Context, id int64) (localdns.Record, error) {
	record, ok := s.records[id]
	if !ok {
		return localdns.Record{}, localdns.ErrNotFound
	}
	return record, nil
}

func (s *fakeLocalDNSStore) Update(_ context.Context, id int64, input localdns.RecordInput) (localdns.Record, error) {
	current, ok := s.records[id]
	if !ok {
		return localdns.Record{}, localdns.ErrNotFound
	}
	next, err := localdns.NewRecord(input)
	if err != nil {
		return localdns.Record{}, err
	}
	next.ID = id
	next.CreatedAt = current.CreatedAt
	next.UpdatedAt = current.UpdatedAt.Add(time.Second)
	s.records[id] = next
	return next, nil
}

func (s *fakeLocalDNSStore) Delete(_ context.Context, id int64) error {
	if _, ok := s.records[id]; !ok {
		return localdns.ErrNotFound
	}
	delete(s.records, id)
	return nil
}

func (s *fakeLocalDNSStore) ListEnabled(context.Context) ([]localdns.Record, error) {
	return nil, errors.New("unused")
}
