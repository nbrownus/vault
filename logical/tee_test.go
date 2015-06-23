package logical

import (
	"net/http"
	"testing"
	"bytes"
	"fmt"
)

func TestTeeHeaderResponseWriter(t *testing.T) {
	w0 := &testResponseWriter{}
	w := NewTeeHeaderResponseWriter(w0)
	r, _ := http.NewRequest("GET", "http://example.com/foo", nil)

	s := http.NewServeMux()
	s.HandleFunc("/foo", func (res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		res.Header().Add("X-Foo", "bar")
	})

	s.ServeHTTP(w, r)

	if w0.StatusCode != w.StatusCode {
		t.Fatal(w.StatusCode)
	}

	if w0.Header().Get("X-Foo") != w.Header().Get("X-Foo") {
		t.Fatal(w.Header())
	}
}

func TestTeeResponseWriter(t *testing.T) {
	w0 := &testResponseWriter{}
	w := NewTeeResponseWriter(w0)
	r, _ := http.NewRequest("GET", "http://example.com/foo", nil)

	s := http.NewServeMux()
	s.HandleFunc("/foo", func (res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		res.Header().Add("X-Foo", "bar")
		fmt.Fprint(res, "Hello there")
	})

	s.ServeHTTP(w, r)

	if w0.StatusCode != w.StatusCode {
		t.Fatal(w.StatusCode)
	}

	if w0.Header().Get("X-Foo") != w.Header().Get("X-Foo") {
		t.Fatal(w.Header())
	}

	if w0.Body.String() != w.Body.String() || w0.Body.String() != "Hello there" {
		t.Fatal(w.Body.String())
	}
}

type testResponseWriter struct {
	Body        bytes.Buffer
	StatusCode  int
	WroteHeader bool
	header      http.Header
}

func (w *testResponseWriter) Header() http.Header {
	if nil == w.header {
		w.header = make(map[string][]string)
	}
	return w.header
}

func (w *testResponseWriter) Write(p []byte) (int, error) {
	return w.Body.Write(p)
}

func (w *testResponseWriter) WriteHeader(code int) {
	w.StatusCode = code
	w.WroteHeader = true
}
