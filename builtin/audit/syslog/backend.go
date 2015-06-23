package file

import (
	"bytes"
	"strconv"

	"github.com/hashicorp/go-syslog"
	"github.com/hashicorp/vault/audit"
	"github.com/hashicorp/vault/logical"
	"github.com/mitchellh/copystructure"
	"net/http"
	"strings"
)

func Factory(conf map[string]string) (audit.Backend, error) {
	// Get facility or default to AUTH
	facility, ok := conf["facility"]
	if !ok {
		facility = "AUTH"
	}

	// Get tag or default to 'vault'
	tag, ok := conf["tag"]
	if !ok {
		tag = "vault"
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

	// Get the logger
	logger, err := gsyslog.NewLogger(gsyslog.LOG_INFO, facility, tag)
	if err != nil {
		return nil, err
	}

	b := &Backend{
		logger: logger,
		LogRaw: logRaw,
		LogHTTP: logHTTP,
	}
	return b, nil
}

// Backend is the audit backend for the syslog-based audit store.
type Backend struct {
	logger gsyslog.Syslogger
	LogRaw bool
	LogHTTP bool
}

func (b *Backend) LogRequest(auth *logical.Auth, req *logical.Request) error {
	if b.LogHTTP {
		return nil
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

	// Encode the entry as JSON
	var buf bytes.Buffer
	var format audit.FormatJSON
	if err := format.FormatRequest(&buf, auth, req); err != nil {
		return err
	}

	// Write out to syslog
	_, err := b.logger.Write(buf.Bytes())
	return err
}

func (b *Backend) LogResponse(auth *logical.Auth, req *logical.Request,
	resp *logical.Response, err error) error {
	if b.LogHTTP {
		return nil
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

	// Encode the entry as JSON
	var buf bytes.Buffer
	var format audit.FormatJSON
	if err := format.FormatResponse(&buf, auth, req, resp, err); err != nil {
		return err
	}

	// Write otu to syslog
	_, err = b.logger.Write(buf.Bytes())
	return err
}

func (b *Backend) LogHTTPRequest(req *http.Request, resp *logical.TeeResponseWriter) error {
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

	// Encode the entry as JSON
	var buf bytes.Buffer
	var format audit.FormatJSON
	err := format.FormatHTTPRequest(&buf, *req, *resp);
	if err != nil {
		return err
	}

	// Write otu to syslog
	_, err = b.logger.Write(buf.Bytes())
	return err
}

func sanitizeHeader(h http.Header) http.Header {
	newHeader := make(http.Header)
	for name, values := range h {
		newName := strings.ToLower(name)
		newHeader[newName] = append(newHeader[newName], strings.Join(values, "; "))
	}
	return newHeader
}
