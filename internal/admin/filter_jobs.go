package admin

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bjhaid/corehole/internal/filter"
)

var errRefreshQueueFull = errors.New("refresh queue is full")

type RefreshJob struct {
	ID        string       `json:"id"`
	ListID    int64        `json:"list_id"`
	Status    string       `json:"status"`
	Phase     string       `json:"phase"`
	StatusURL string       `json:"status_url"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
	Error     string       `json:"error,omitempty"`
	Result    *filter.List `json:"result,omitempty"`
}

func (j RefreshJob) active() bool { return j.Status == "queued" || j.Status == "running" }

// RefreshJobs owns one worker, independent of HTTP request lifetimes. A
// separate, small database keeps admission and polling responsive during a
// long write transaction in the filtering database.
type RefreshJobs struct {
	mu       sync.Mutex
	jobs     map[string]RefreshJob
	queue    []string
	wake     chan struct{}
	done     chan struct{}
	cancel   context.CancelFunc
	ctx      context.Context
	db       *sql.DB
	service  FilterService
	reloader FilterReloader
}

func NewRefreshJobs(parent context.Context, service FilterService, reloader FilterReloader, db *sql.DB) (*RefreshJobs, error) {
	ctx, cancel := context.WithCancel(parent)
	j := &RefreshJobs{jobs: make(map[string]RefreshJob), wake: make(chan struct{}, 1), done: make(chan struct{}), cancel: cancel, ctx: ctx, db: db, service: service, reloader: reloader}
	if db != nil {
		rows, err := db.QueryContext(ctx, "SELECT payload FROM refresh_jobs ORDER BY rowid")
		if err != nil {
			cancel()
			return nil, err
		}
		var recovered []RefreshJob
		for rows.Next() {
			var payload string
			var job RefreshJob
			if err := rows.Scan(&payload); err != nil {
				_ = rows.Close()
				cancel()
				return nil, err
			}
			if err := json.Unmarshal([]byte(payload), &job); err != nil {
				_ = rows.Close()
				cancel()
				return nil, err
			}
			if job.active() {
				job.Status, job.Phase, job.Error = "queued", "queued", ""
				job.UpdatedAt = time.Now().UTC()
				j.queue = append(j.queue, job.ID)
				recovered = append(recovered, job)
			}
			j.jobs[job.ID] = job
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			cancel()
			return nil, err
		}
		for _, job := range recovered {
			if err := j.save(job); err != nil {
				cancel()
				return nil, err
			}
		}
	}
	go j.run()
	j.signal()
	return j, nil
}

func (j *RefreshJobs) save(job RefreshJob) error {
	if j.db == nil {
		return nil
	}
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = j.db.ExecContext(ctx, "INSERT INTO refresh_jobs(id,payload) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", job.ID, string(data))
	return err
}

func (j *RefreshJobs) Submit(listID int64) (RefreshJob, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.ctx.Err(); err != nil {
		return RefreshJob{}, err
	}
	active := 0
	for _, job := range j.jobs {
		if job.active() {
			if job.ListID == listID {
				return job, nil
			}
			active++
		}
	}
	if active >= 64 {
		return RefreshJob{}, errRefreshQueueFull
	}
	if len(j.jobs) >= 256 {
		var oldest RefreshJob
		for _, job := range j.jobs {
			if !job.active() && (oldest.ID == "" || job.CreatedAt.Before(oldest.CreatedAt)) {
				oldest = job
			}
		}
		if oldest.ID != "" {
			if j.db != nil {
				if _, err := j.db.ExecContext(j.ctx, "DELETE FROM refresh_jobs WHERE id=?", oldest.ID); err != nil {
					return RefreshJob{}, err
				}
			}
			delete(j.jobs, oldest.ID)
		}
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return RefreshJob{}, err
	}
	id := hex.EncodeToString(token[:])
	now := time.Now().UTC()
	job := RefreshJob{ID: id, ListID: listID, Status: "queued", Phase: "queued", StatusURL: "/api/filter/jobs/" + id, CreatedAt: now, UpdatedAt: now}
	if err := j.save(job); err != nil {
		return RefreshJob{}, err
	}
	j.jobs[id] = job
	j.queue = append(j.queue, id)
	j.signal()
	return job, nil
}

func (j *RefreshJobs) signal() {
	select {
	case j.wake <- struct{}{}:
	default:
	}
}

func (j *RefreshJobs) Get(id string) (RefreshJob, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	job, ok := j.jobs[id]
	return job, ok
}

func (j *RefreshJobs) List(activeOnly bool) []RefreshJob {
	j.mu.Lock()
	defer j.mu.Unlock()
	jobs := make([]RefreshJob, 0, len(j.jobs))
	for _, job := range j.jobs {
		if !activeOnly || job.active() {
			jobs = append(jobs, job)
		}
	}
	sort.Slice(jobs, func(a, b int) bool { return jobs[a].CreatedAt.After(jobs[b].CreatedAt) })
	return jobs
}

func (j *RefreshJobs) update(job RefreshJob) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	job.UpdatedAt = time.Now().UTC()
	if err := j.save(job); err != nil {
		return err
	}
	j.jobs[job.ID] = job
	return nil
}

func (j *RefreshJobs) run() {
	defer close(j.done)
	for {
		select {
		case <-j.ctx.Done():
			return
		case <-j.wake:
		}
		for j.ctx.Err() == nil {
			j.mu.Lock()
			if len(j.queue) == 0 {
				j.mu.Unlock()
				break
			}
			id := j.queue[0]
			j.queue = j.queue[1:]
			job := j.jobs[id]
			j.mu.Unlock()
			job.Status, job.Phase = "running", "refreshing"
			if err := j.update(job); err != nil {
				j.fail(job, err)
				continue
			}
			list, err := j.service.RefreshList(j.ctx, job.ListID)
			if err == nil {
				job.Result = &list
				job.Phase = "reloading"
				err = j.update(job)
				if err == nil && j.reloader != nil {
					err = j.reloader.Reload(j.ctx)
				}
			}
			if j.ctx.Err() != nil {
				job.Status, job.Phase, job.Error = "queued", "queued", ""
				_ = j.update(job)
				return
			}
			if err != nil {
				j.fail(job, err)
				continue
			}
			job.Status, job.Phase = "succeeded", "complete"
			if err := j.update(job); err != nil {
				j.fail(job, err)
			}
		}
	}
}

func (j *RefreshJobs) fail(job RefreshJob, err error) {
	job.Status, job.Error = "failed", err.Error()
	if saveErr := j.update(job); saveErr != nil {
		j.mu.Lock()
		job.Error += "; job persistence: " + saveErr.Error()
		j.jobs[job.ID] = job
		j.mu.Unlock()
	}
}

func (j *RefreshJobs) Close(ctx context.Context) error {
	j.cancel()
	select {
	case <-j.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func WithRefreshJobs(jobs *RefreshJobs) Option {
	return func(s *Server) { s.filterJobs = jobs; s.filterJobsProvided = true }
}

func (s *Server) refreshJobs() (*RefreshJobs, error) {
	s.filterJobsMu.Lock()
	defer s.filterJobsMu.Unlock()
	if s.filterJobs == nil && !s.filterJobsProvided {
		jobs, err := NewRefreshJobs(context.Background(), s.filterService, s.filterReloader, nil)
		if err != nil {
			return nil, err
		}
		s.filterJobs = jobs
	}
	if s.filterJobs == nil {
		return nil, fmt.Errorf("refresh jobs unavailable")
	}
	return s.filterJobs, nil
}

func (s *Server) handleFilterJobs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	jobs, err := s.refreshJobs()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "refresh_jobs_unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/api/filter/jobs" {
		writeJSON(w, http.StatusOK, map[string][]RefreshJob{"jobs": jobs.List(r.URL.Query().Get("active") == "true")})
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/filter/jobs/")
	job, ok := jobs.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "refresh_job_not_found")
		return
	}
	writeJSON(w, http.StatusOK, job)
}
