package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// A token is a shared secret for the API: with Server.Token set, every
// request must carry "Authorization: Bearer <token>". It is what makes the
// API safe to reach from other machines, or from other users on a shared
// one. Loopback without a token stays the zero setup default.

// ReadToken reads a token file, as written by LoadOrCreateToken.
func ReadToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	t := strings.TrimSpace(string(b))
	if len(t) < 16 {
		return "", fmt.Errorf("token in %s is shorter than 16 characters", path)
	}
	return t, nil
}

// LoadOrCreateToken reads the token at path, or writes a new random one
// there, readable only by its owner, if the file does not exist.
func LoadOrCreateToken(path string) (token string, created bool, err error) {
	token, err = ReadToken(path)
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		return token, false, err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", false, err
	}
	token = hex.EncodeToString(b)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", false, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", false, err
	}
	if _, err := f.WriteString(token + "\n"); err != nil {
		f.Close()
		return "", false, err
	}
	return token, true, f.Close()
}

// authorized reports whether r carries the server's token.
func (s *Server) authorized(r *http.Request) bool {
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) == 1
}
