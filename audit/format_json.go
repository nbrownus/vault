package audit

import (
	"encoding/json"
	"io"

	"github.com/hashicorp/vault/logical"
	"time"
	"net/http"
	"fmt"
	"strings"
	"net"
)

// FormatJSON is a Formatter implementation that structuteres data into
// a JSON format.
type FormatJSON struct{}

func (f *FormatJSON) FormatRequest(
	w io.Writer,
	auth *logical.Auth, req *logical.Request) error {
	// If auth is nil, make an empty one
	if auth == nil {
		auth = new(logical.Auth)
	}

	// Encode!
	enc := json.NewEncoder(w)
	return enc.Encode(&JSONRequestEntry{
		Type: "request",

		Auth: JSONAuth{
			DisplayName: auth.DisplayName,
			Policies:    auth.Policies,
			Metadata:    auth.Metadata,
		},

		Request: JSONRequest{
			Operation: req.Operation,
			Path:      req.Path,
			Data:      req.Data,
		},
	})
}

func (f *FormatJSON) FormatResponse(
	w io.Writer,
	auth *logical.Auth,
	req *logical.Request,
	resp *logical.Response,
	err error) error {
	// If things are nil, make empty to avoid panics
	if auth == nil {
		auth = new(logical.Auth)
	}
	if resp == nil {
		resp = new(logical.Response)
	}

	var respAuth JSONAuth
	if resp.Auth != nil {
		respAuth = JSONAuth{
			ClientToken: resp.Auth.ClientToken,
			DisplayName: resp.Auth.DisplayName,
			Policies:    resp.Auth.Policies,
			Metadata:    resp.Auth.Metadata,
		}
	}

	var respSecret JSONSecret
	if resp.Secret != nil {
		respSecret = JSONSecret{
			LeaseID: resp.Secret.LeaseID,
		}
	}

	// Encode!
	enc := json.NewEncoder(w)
	return enc.Encode(&JSONResponseEntry{
		Type: "response",

		Auth: JSONAuth{
			Policies: auth.Policies,
			Metadata: auth.Metadata,
		},

		Request: JSONRequest{
			Operation: req.Operation,
			Path:      req.Path,
			Data:      req.Data,
		},

		Response: JSONResponse{
			Auth:     respAuth,
			Secret:   respSecret,
			Data:     resp.Data,
			Redirect: resp.Redirect,
		},
	})
}

func (f *FormatJSON) FormatHTTPRequest(w io.Writer, req http.Request, res logical.TeeResponseWriter) error {
	enc := json.NewEncoder(w)
	return enc.Encode(&JSONHTTPEntry{
		Type: "http",

		Duration: res.Duration / time.Millisecond,

		HTTP: JSONHTTP{
			Request: JSONHTTPRequest{
				Body:          req.Body.(*logical.TeeReadCloser).Bytes.String(),
				Header:        f.formatHTTPHeader(req.Header),
				Method:        req.Method,
				Path:          req.URL.RequestURI(),
				RemoteAddress: getHost(req.RemoteAddr),
			},

			Response: JSONHTTPResponse{
				Body:       res.Body.String(),
				Header:     f.formatHTTPHeader(res.Header()),
				StatusCode: res.StatusCode,
				StatusText: http.StatusText(res.StatusCode),
			},

			Version: fmt.Sprintf("%d.%d", req.ProtoMajor, req.ProtoMinor),
		},

		Message: fmt.Sprintf(
			"%s %s %s\n%s %d %s",
			req.Method,
			req.URL.RequestURI(),
			req.Proto,
			req.Proto,
			res.StatusCode,
			http.StatusText(res.StatusCode),
		),
	})
}

func (f *FormatJSON) formatHTTPHeader(h http.Header) map[string]string {
	header := make(map[string]string)

	for name, values := range h {
		header[strings.ToLower(name)] = strings.Join(values, "; ")
	}

	return header
}

func getHost(hostport string) (host string) {
	var remoteAddr string

	remoteAddr, _, err := net.SplitHostPort(hostport)
	if err != nil {
		remoteAddr = ""
	}

	return remoteAddr
}

// JSONRequest is the structure of a request audit log entry in JSON.
type JSONRequestEntry struct {
	Type    string      `json:"type"`
	Auth    JSONAuth    `json:"auth"`
	Request JSONRequest `json:"request"`
}

// JSONResponseEntry is the structure of a response audit log entry in JSON.
type JSONResponseEntry struct {
	Type     string       `json:"type"`
	Error    string       `json:"error"`
	Auth     JSONAuth     `json:"auth"`
	Request  JSONRequest  `json:"request"`
	Response JSONResponse `json:"response"`
}

type JSONRequest struct {
	Operation logical.Operation      `json:"operation"`
	Path      string                 `json:"path"`
	Data      map[string]interface{} `json:"data"`
}

type JSONResponse struct {
	Auth     JSONAuth               `json:"auth,omitempty"`
	Secret   JSONSecret             `json:"secret,emitempty"`
	Data     map[string]interface{} `json:"data"`
	Redirect string                 `json:"redirect"`
}

type JSONAuth struct {
	ClientToken string            `json:"client_token,omitempty"`
	DisplayName string            `json:"display_name"`
	Policies    []string          `json:"policies"`
	Metadata    map[string]string `json:"metadata"`
}

type JSONSecret struct {
	LeaseID string `json:"lease_id"`
}

type JSONHTTPEntry struct {
	Duration  time.Duration `json:"duration"`
	HTTP      JSONHTTP      `json:"http"`
	Message   string        `json:"message"`
	Type      string        `json:"type"`
}

type JSONHTTP struct {
	Request  JSONHTTPRequest  `json:"request"`
	Response JSONHTTPResponse `json:"response"`
	Version  string           `json:"version"`
}

type JSONHTTPRequest struct {
	Body          string            `json:"body"`
	Header        map[string]string `json:"headers"`
	Method        string            `json:"method"`
	Path          string            `json:"url"`
	RemoteAddress string            `json:"remote_address"`
}

type JSONHTTPResponse struct {
	Body       string            `json:"body"`
	Header     map[string]string `json:"headers"`
	StatusText string            `json:"reason"`
	StatusCode int               `json:"status"`
}
