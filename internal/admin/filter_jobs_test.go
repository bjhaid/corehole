package admin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bjhaid/corehole/internal/filter"
	"github.com/bjhaid/corehole/internal/storage"
)

type refreshTestService struct {
	FilterService
	refresh func(context.Context, int64) (filter.List, error)
}

func (s refreshTestService) GetList(_ context.Context, id int64) (filter.List, error) {
	if id == 999 {
		return filter.List{}, filter.ErrNotFound
	}
	return filter.List{ID: id, Enabled: true}, nil
}
func (s refreshTestService) RefreshList(ctx context.Context, id int64) (filter.List, error) {
	return s.refresh(ctx, id)
}

type refreshReloaderFunc func(context.Context) error

func (f refreshReloaderFunc) Reload(ctx context.Context) error { return f(ctx) }

func closeRefreshJobs(t *testing.T, jobs *RefreshJobs) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := jobs.Close(ctx); err != nil {
		t.Errorf("close refresh jobs: %v", err)
	}
}

func waitRefreshJob(t *testing.T, jobs *RefreshJobs, id string) RefreshJob {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		job, ok := jobs.Get(id)
		if ok && !job.active() {
			return job
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("refresh job did not finish")
	return RefreshJob{}
}

func TestRefreshAlwaysAcceptedDetachedDeduplicatedAndSerialized(t *testing.T) {
	entered := make(chan int64, 2)
	release := make(chan struct{})
	service := refreshTestService{refresh: func(ctx context.Context, id int64) (filter.List, error) {
		entered <- id
		if id == 1 {
			select {
			case <-release:
			case <-ctx.Done():
				return filter.List{}, ctx.Err()
			}
		}
		return filter.List{ID: id}, nil
	}}
	jobs, err := NewRefreshJobs(context.Background(), service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRefreshJobs(t, jobs)
	server := newTestServer(WithFilterService(service), WithRefreshJobs(jobs))
	cookie := setupSession(t, server)
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/api/filter/lists/1/refresh?wait=true", nil).WithContext(ctx)
	req.AddCookie(cookie)
	res := httptest.NewRecorder()
	returned := make(chan struct{})
	go func() { server.ServeHTTP(res, req); close(returned) }()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("refresh request waited for work")
	}
	if res.Code != http.StatusAccepted {
		t.Fatalf("refresh: %d %s", res.Code, res.Body.String())
	}
	job := decodeResponse[RefreshJob](t, res)
	if res.Header().Get("Location") != job.StatusURL || res.Header().Get("Retry-After") == "" {
		t.Fatal("missing polling headers")
	}
	if id := <-entered; id != 1 {
		t.Fatalf("started list %d", id)
	}
	cancel()
	duplicate := postJSON(t, server, "/api/filter/lists/1/refresh", nil, cookie)
	if duplicate.Code != http.StatusAccepted || decodeResponse[RefreshJob](t, duplicate).ID != job.ID {
		t.Fatal("duplicate refresh was not deduplicated")
	}
	second := postJSON(t, server, "/api/filter/lists/2/refresh", nil, cookie)
	if second.Code != http.StatusAccepted {
		t.Fatalf("second admission blocked: %s", second.Body.String())
	}
	secondJob := decodeResponse[RefreshJob](t, second)
	if secondJob.Status != "queued" {
		t.Fatalf("second job ran concurrently: %+v", secondJob)
	}
	select {
	case id := <-entered:
		t.Fatalf("concurrent refresh %d", id)
	default:
	}
	status := get(t, server, job.StatusURL, cookie)
	if status.Code != http.StatusOK || decodeResponse[RefreshJob](t, status).Status != "running" {
		t.Fatalf("job canceled with request: %s", status.Body.String())
	}
	if get(t, server, job.StatusURL, nil).Code != http.StatusUnauthorized {
		t.Fatal("job status must require authentication")
	}
	if postJSON(t, server, job.StatusURL, nil, cookie).Code != http.StatusMethodNotAllowed {
		t.Fatal("job status must be GET only")
	}
	if get(t, server, "/api/filter/jobs/missing", cookie).Code != http.StatusNotFound {
		t.Fatal("missing job must return 404")
	}
	if postJSON(t, server, "/api/filter/lists/999/refresh", nil, cookie).Code != http.StatusNotFound {
		t.Fatal("missing list must not enqueue")
	}
	close(release)
	if waitRefreshJob(t, jobs, job.ID).Status != "succeeded" {
		t.Fatal("detached job failed")
	}
	if waitRefreshJob(t, jobs, secondJob.ID).Status != "succeeded" {
		t.Fatal("queued job failed")
	}
	if id := <-entered; id != 2 {
		t.Fatalf("wrong second refresh: %d", id)
	}
}

func TestRefreshJobFinishesOnlyAfterReload(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	service := refreshTestService{refresh: func(context.Context, int64) (filter.List, error) { return filter.List{ID: 1}, nil }}
	reloader := refreshReloaderFunc(func(ctx context.Context) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	jobs, err := NewRefreshJobs(context.Background(), service, reloader, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRefreshJobs(t, jobs)
	job, err := jobs.Submit(1)
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	current, _ := jobs.Get(job.ID)
	if current.Status != "running" || current.Phase != "reloading" {
		t.Fatalf("reported completion before activation: %+v", current)
	}
	close(release)
	if finished := waitRefreshJob(t, jobs, job.ID); finished.Status != "succeeded" || finished.Result == nil {
		t.Fatalf("job: %+v", finished)
	}
}

func TestRefreshJobReportsImportAndReloadFailures(t *testing.T) {
	for _, phase := range []string{"refreshing", "reloading"} {
		t.Run(phase, func(t *testing.T) {
			service := refreshTestService{refresh: func(context.Context, int64) (filter.List, error) {
				if phase == "refreshing" {
					return filter.List{}, errors.New("import failed")
				}
				return filter.List{ID: 1}, nil
			}}
			reloader := refreshReloaderFunc(func(context.Context) error { return errors.New("activation failed") })
			jobs, err := NewRefreshJobs(context.Background(), service, reloader, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer closeRefreshJobs(t, jobs)
			job, err := jobs.Submit(1)
			if err != nil {
				t.Fatal(err)
			}
			finished := waitRefreshJob(t, jobs, job.ID)
			if finished.Status != "failed" || finished.Phase != phase || !strings.Contains(finished.Error, "failed") {
				t.Fatalf("job: %+v", finished)
			}
		})
	}
}

func TestRefreshJobsSurviveRestart(t *testing.T) {
	ctx := context.Background()
	store, err := storage.OpenJobs(ctx, filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close(ctx) }()
	entered := make(chan struct{})
	blocked := refreshTestService{refresh: func(ctx context.Context, _ int64) (filter.List, error) {
		close(entered)
		<-ctx.Done()
		return filter.List{}, ctx.Err()
	}}
	jobs, err := NewRefreshJobs(ctx, blocked, nil, store.DB())
	if err != nil {
		t.Fatal(err)
	}
	job, err := jobs.Submit(1)
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	closeRefreshJobs(t, jobs)
	// Simulate an unclean exit that left a durable running record behind.
	job.Status, job.Phase = "running", "refreshing"
	if err := jobs.save(job); err != nil {
		t.Fatal(err)
	}
	service := refreshTestService{refresh: func(context.Context, int64) (filter.List, error) { return filter.List{ID: 1, Enabled: true}, nil }}
	restarted, err := NewRefreshJobs(ctx, service, nil, store.DB())
	if err != nil {
		t.Fatal(err)
	}
	finished := waitRefreshJob(t, restarted, job.ID)
	if finished.Status != "succeeded" || finished.Result == nil {
		t.Fatalf("recovered job: %+v", finished)
	}
	closeRefreshJobs(t, restarted)
	again, err := NewRefreshJobs(ctx, service, nil, store.DB())
	if err != nil {
		t.Fatal(err)
	}
	defer closeRefreshJobs(t, again)
	if persisted, ok := again.Get(job.ID); !ok || persisted.Status != "succeeded" {
		t.Fatalf("lost completion: %+v", persisted)
	}
}

func TestRefreshQueueUnavailableNeverFallsBackToInline(t *testing.T) {
	called := false
	service := refreshTestService{refresh: func(context.Context, int64) (filter.List, error) { called = true; return filter.List{}, nil }}
	server := newTestServer(WithFilterService(service), WithRefreshJobs(nil))
	cookie := setupSession(t, server)
	res := postJSON(t, server, "/api/filter/lists/1/refresh", nil, cookie)
	if res.Code != http.StatusServiceUnavailable || called {
		t.Fatalf("unexpected inline fallback: %d called=%t", res.Code, called)
	}
}

func TestRefreshQueueIsBounded(t *testing.T) {
	service := refreshTestService{refresh: func(ctx context.Context, _ int64) (filter.List, error) { <-ctx.Done(); return filter.List{}, ctx.Err() }}
	jobs, err := NewRefreshJobs(context.Background(), service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRefreshJobs(t, jobs)
	for id := int64(1); id <= 64; id++ {
		if _, err := jobs.Submit(id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := jobs.Submit(65); !errors.Is(err, errRefreshQueueFull) {
		t.Fatalf("unbounded queue: %v", err)
	}
}
