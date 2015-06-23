package file

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/hashicorp/vault/audit"
	"github.com/hashicorp/vault/logical"
	"github.com/mitchellh/copystructure"
	"net/http"
	"strings"
)

func Factory(conf map[string]string) (audit.Backend, error) {
	path, ok := conf["path"]
	if !ok {
		return nil, fmt.Errorf("path is required")
	}

	// Check if raw logging is enabled
	logRaw := false
	if raw, ok := conf["log_raw"]; ok {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, err
		}
		logRaw = b
	}

	// Check if http logging is enabled
	logHTTP := false
	if raw, ok := conf["log_http"]; ok {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, err
		}
		logHTTP = b
	}

	b := &Backend{
		Path:    path,
		LogRaw:  logRaw,
		LogHTTP: logHTTP,
	}
	return b, nil
}

// Backend is the audit backend for the file-based audit store.
//
// NOTE: This audit backend is currently very simple: it appends to a file.
// It doesn't do anything more at the moment to assist with rotation
// or reset the write cursor, this should be done in the future.
type Backend struct {
	Path    string
	LogRaw  bool
	LogHTTP bool

	once sync.Once
	f    *os.File
}

func (b *Backend) LogRequest(auth *logical.Auth, req *logical.Request) error {
	if b.LogHTTP {
		return nil
	}
	if err := b.open(); err != nil {
		return err
	}
	if !b.LogRaw {
		// Copy the structures
		cp, err := copystructure.Copy(auth)
		if err != nil {
			return err
		}
		auth = cp.(*logical.Auth)

		cp, err = copystructure.Copy(req)
		if err != nil {
			return err
		}
		req = cp.(*logical.Request)

		// Hash any sensitive information
		if err := audit.Hash(auth); err != nil {
			return err
		}
		if err := audit.Hash(req); err != nil {
			return err
		}
	}

	var format audit.FormatJSON
	return format.FormatRequest(b.f, auth, req)
}

func (b *Backend) LogResponse(
	auth *logical.Auth,
	req *logical.Request,
	resp *logical.Response,
	err error) error {
	if b.LogHTTP {
		return nil
	}
	if err := b.open(); err != nil {
		return err
	}
	if !b.LogRaw {
		// Copy the structure
		cp, err := copystructure.Copy(auth)
		if err != nil {
			return err
		}
		auth = cp.(*logical.Auth)

		cp, err = copystructure.Copy(req)
		if err != nil {
			return err
		}
		req = cp.(*logical.Request)

		cp, err = copystructure.Copy(resp)
		if err != nil {
			return err
		}
		resp = cp.(*logical.Response)

		// Hash any sensitive information
		if err := audit.Hash(auth); err != nil {
			return err
		}
		if err := audit.Hash(req); err != nil {
			return err
		}
		if err := audit.Hash(resp); err != nil {
			return err
		}
	}

	var format audit.FormatJSON
	return format.FormatResponse(b.f, auth, req, resp, err)
}

func (b *Backend) LogHTTPRequest(req *http.Request, resp *logical.TeeResponseWriter) error {
	if err := b.open(); err != nil {
		return err
	}

	if !b.LogHTTP {
		return nil
	}

	// Prime resp.RawHeader
	resp.Header()

	req.Header = sanitizeHeader(req.Header)
	resp.RawHeader = sanitizeHeader(resp.RawHeader)

	if !b.LogRaw {
		if err := audit.Hash(req); err != nil {
			return err
		}

		if err := audit.Hash(resp); err != nil {
			return err
		}
	}

	var format audit.FormatJSON
	return format.FormatHTTPRequest(b.f, *req, *resp)
}

func (b *Backend) open() error {
	if b.f != nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(b.Path), 0600); err != nil {
		return err
	}

	var err error
	b.f, err = os.OpenFile(b.Path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	return nil
}

func sanitizeHeader(h http.Header) http.Header {
	newHeader := make(http.Header)
	for name, values := range h {
		newName := strings.ToLower(name)
		newHeader[newName] = append(newHeader[newName], strings.Join(values, "; "))
	}
	return newHeader
}
