// Package lists builds a blocklist set from local files and URLs.
//
// Every URL that downloads successfully is also saved to a cache directory.
// If a later download fails (no network at boot, the host is down), the
// saved copy is used instead, so the sinkhole never starts with nothing.
package lists

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"eventhorizon/internal/policy"
)

// DefaultMaxBytes caps a single download. The biggest common lists are a
// few megabytes; anything far beyond that is a mistake or an attack.
const DefaultMaxBytes = 64 << 20

type Loader struct {
	Client   *http.Client
	CacheDir string
	MaxBytes int64
}

// Report says what happened to one source.
type Report struct {
	Source    string
	Added     int   // domains this source added that earlier ones had not
	FromCache bool  // download failed, the saved copy was used
	Err       error // the download or read error, if any
}

// Failed reports whether this source contributed nothing usable.
func (r Report) Failed() bool {
	return r.Err != nil && !r.FromCache
}

func IsURL(src string) bool {
	return strings.HasPrefix(src, "https://") || strings.HasPrefix(src, "http://")
}

// Build loads every source into one new set. It never stops early: each
// source gets its own Report so the caller decides what counts as fatal.
func (l *Loader) Build(ctx context.Context, sources []string) (*policy.Set, []Report) {
	set := policy.NewSet()
	reports := make([]Report, 0, len(sources))
	for _, src := range sources {
		reports = append(reports, l.loadOne(ctx, set, src))
	}
	return set, reports
}

func (l *Loader) loadOne(ctx context.Context, set *policy.Set, src string) Report {
	rep := Report{Source: src}

	var data []byte
	if IsURL(src) {
		var err error
		data, err = l.fetch(ctx, src)
		if err == nil {
			if cerr := l.saveCache(src, data); cerr != nil {
				// Not fatal: this run has the data, only the fallback is missing.
				rep.Err = fmt.Errorf("saving cache: %w", cerr)
			}
		} else {
			cached, cerr := os.ReadFile(l.cachePath(src))
			if cerr != nil {
				rep.Err = err
				return rep
			}
			data, rep.FromCache, rep.Err = cached, true, err
		}
	} else {
		var err error
		data, err = os.ReadFile(src)
		if err != nil {
			rep.Err = err
			return rep
		}
	}

	n, err := set.Load(bytes.NewReader(data))
	rep.Added = n
	if err != nil {
		rep.Err = err
	}
	return rep
}

func (l *Loader) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "eventhorizon-dns-sinkhole")

	resp, err := l.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}

	limit := l.MaxBytes
	if limit <= 0 {
		limit = DefaultMaxBytes
	}
	// Read one byte past the limit so we can tell "exactly at" from "over".
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("GET %s: larger than %d bytes", url, limit)
	}
	return data, nil
}

// cachePath gives every URL a stable file name: a short hash of the URL,
// so any characters in the URL are safe on disk.
func (l *Loader) cachePath(url string) string {
	sum := sha256.Sum256([]byte(url))
	return filepath.Join(l.CacheDir, hex.EncodeToString(sum[:8])+".txt")
}

// saveCache writes to a temporary file and renames it into place, so a
// crash halfway through never leaves a half written list behind.
func (l *Loader) saveCache(url string, data []byte) error {
	if err := os.MkdirAll(l.CacheDir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(l.CacheDir, ".download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), l.cachePath(url))
}