package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestTokenRequiredOnEveryRequest(t *testing.T) {
	s, _, _ := newAPI(t)
	s.Token = "0123456789abcdef0123456789abcdef"

	for _, auth := range []string{"", "Bearer wrong", "0123456789abcdef0123456789abcdef", "Basic 0123456789abcdef0123456789abcdef"} {
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:5380/api/stats", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q: status %d, want 401", auth, w.Code)
		}
	}
}

func TestTokenReplacesTheHostCheck(t *testing.T) {
	s, _, _ := newAPI(t)
	s.Token = "0123456789abcdef0123456789abcdef"
	// With a token the API may listen on a LAN address and be reached by
	// that address; the token is the protection, not the Host header.
	r := httptest.NewRequest(http.MethodGet, "http://192.168.1.10:5380/api/stats", nil)
	r.Header.Set("Authorization", "Bearer "+s.Token)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
}

func TestTokenDoesNotSkipTheChangeHeader(t *testing.T) {
	s, _, _ := newAPI(t)
	s.Control = &fakeControl{}
	s.Token = "0123456789abcdef0123456789abcdef"
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:5380/api/reload", nil)
	r.Header.Set("Authorization", "Bearer "+s.Token)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", w.Code)
	}
}

func TestLoadOrCreateToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "api.token")

	first, created, err := LoadOrCreateToken(path)
	if err != nil || !created || len(first) != 64 {
		t.Fatalf("create: %q created=%v err=%v", first, created, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("token file mode %o, want 600", perm)
	}

	again, created, err := LoadOrCreateToken(path)
	if err != nil || created || again != first {
		t.Fatalf("reload: %q created=%v err=%v", again, created, err)
	}
}

func TestReadTokenRejectsShortTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.token")
	os.WriteFile(path, []byte("short\n"), 0o600)
	if _, err := ReadToken(path); err == nil {
		t.Fatal("a 5 character token was accepted")
	}
	if _, _, err := LoadOrCreateToken(path); err == nil {
		t.Fatal("LoadOrCreateToken replaced or accepted a bad existing file")
	}
}
