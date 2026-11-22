package lists

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const hosts = "# test list\n0.0.0.0 ads.example\n0.0.0.0 tracker.example\n"

// listServer serves hosts at /list until down is set, then returns 503.
func listServer(t *testing.T) (*httptest.Server, *atomic.Bool) {
	t.Helper()
	down := new(atomic.Bool)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case down.Load():
			http.Error(w, "down", http.StatusServiceUnavailable)
		case r.URL.Path == "/list":
			w.Write([]byte(hosts))
		case r.URL.Path == "/huge":
			w.Write([]byte(strings.Repeat("0.0.0.0 a.example\n", 1000)))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, down
}

func newLoader(t *testing.T) *Loader {
	return &Loader{Client: http.DefaultClient, CacheDir: t.TempDir()}
}

func TestURLSource(t *testing.T) {
	srv, _ := listServer(t)
	l := newLoader(t)

	set, reps := l.Build(context.Background(), []string{srv.URL + "/list"})
	if reps[0].Err != nil || reps[0].Added != 2 || reps[0].FromCache {
		t.Fatalf("report = %+v", reps[0])
	}
	if _, ok := set.Match("x.ads.example"); !ok {
		t.Error("list not loaded")
	}
}

func TestFallsBackToCachedCopy(t *testing.T) {
	srv, down := listServer(t)
	l := newLoader(t)
	url := srv.URL + "/list"

	l.Build(context.Background(), []string{url}) // populates the cache
	down.Store(true)

	set, reps := l.Build(context.Background(), []string{url})
	r := reps[0]
	if !r.FromCache || r.Err == nil || r.Failed() {
		t.Fatalf("report = %+v, want cache fallback with the error kept", r)
	}
	if set.Len() != 2 {
		t.Errorf("len = %d", set.Len())
	}
}

func TestFailsWithoutCache(t *testing.T) {
	srv, down := listServer(t)
	down.Store(true)
	_, reps := newLoader(t).Build(context.Background(), []string{srv.URL + "/list"})
	if !reps[0].Failed() {
		t.Errorf("report = %+v, want failure", reps[0])
	}
}

func TestHTTPErrorStatus(t *testing.T) {
	srv, _ := listServer(t)
	_, reps := newLoader(t).Build(context.Background(), []string{srv.URL + "/missing"})
	if !reps[0].Failed() || !strings.Contains(reps[0].Err.Error(), "404") {
		t.Errorf("report = %+v", reps[0])
	}
}

func TestSizeLimit(t *testing.T) {
	srv, _ := listServer(t)
	l := newLoader(t)
	l.MaxBytes = 100
	_, reps := l.Build(context.Background(), []string{srv.URL + "/huge"})
	if !reps[0].Failed() || !strings.Contains(reps[0].Err.Error(), "larger than") {
		t.Errorf("report = %+v", reps[0])
	}
}

func TestFileSourceAndMixing(t *testing.T) {
	srv, _ := listServer(t)
	path := filepath.Join(t.TempDir(), "local.txt")
	os.WriteFile(path, []byte("ads.example\nlocal.example\n"), 0o644)

	set, reps := newLoader(t).Build(context.Background(), []string{srv.URL + "/list", path})
	// ads.example is in both; the second source only adds local.example.
	if reps[0].Added != 2 || reps[1].Added != 1 || set.Len() != 3 {
		t.Errorf("added %d and %d, len %d", reps[0].Added, reps[1].Added, set.Len())
	}
}

func TestMissingFile(t *testing.T) {
	_, reps := newLoader(t).Build(context.Background(), []string{"/nope/does-not-exist"})
	if !reps[0].Failed() {
		t.Errorf("report = %+v", reps[0])
	}
}

func TestCacheLeavesNoTempFiles(t *testing.T) {
	srv, _ := listServer(t)
	l := newLoader(t)
	l.Build(context.Background(), []string{srv.URL + "/list"})

	entries, _ := os.ReadDir(l.CacheDir)
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".txt") {
		t.Errorf("cache dir = %v", entries)
	}
}
