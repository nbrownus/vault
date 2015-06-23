package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-metrics"
	"github.com/hashicorp/vault/audit"
	"github.com/hashicorp/vault/logical"
	"net/http"
	"bytes"
)

const (
	// coreAuditConfigPath is used to store the audit configuration.
	// Audit configuration is protected within the Vault itself, which means it
	// can only be viewed or modified after an unseal.
	coreAuditConfigPath = "core/audit"

	// auditBarrierPrefix is the prefix to the UUID used in the
	// barrier view for the audit backends.
	auditBarrierPrefix = "audit/"
)

var (
	// loadAuditFailed if loading audit tables encounters an error
	loadAuditFailed = errors.New("failed to setup audit table")
)

// enableAudit is used to enable a new audit backend
func (c *Core) enableAudit(entry *MountEntry) error {
	c.audit.Lock()
	defer c.audit.Unlock()

	// Ensure we end the path in a slash
	if !strings.HasSuffix(entry.Path, "/") {
		entry.Path += "/"
	}

	// Ensure there is a name
	if entry.Path == "/" {
		return fmt.Errorf("backend path must be specified")
	}

	// Look for matching name
	for _, ent := range c.audit.Entries {
		switch {
		// Existing is sql/mysql/ new is sql/ or
		// existing is sql/ and new is sql/mysql/
		case strings.HasPrefix(ent.Path, entry.Path):
			fallthrough
		case strings.HasPrefix(entry.Path, ent.Path):
			return fmt.Errorf("path already in use")
		}
	}

	// Lookup the new backend
	backend, err := c.newAuditBackend(entry.Type, entry.Options)
	if err != nil {
		return err
	}

	// Generate a new UUID and view
	entry.UUID = generateUUID()
	view := NewBarrierView(c.barrier, auditBarrierPrefix+entry.UUID+"/")

	// Update the audit table
	newTable := c.audit.Clone()
	newTable.Entries = append(newTable.Entries, entry)
	if err := c.persistAudit(newTable); err != nil {
		return errors.New("failed to update audit table")
	}
	c.audit = newTable

	// Register the backend
	c.auditBroker.Register(entry.Path, backend, view)
	c.logger.Printf("[INFO] core: enabled audit backend '%s' type: %s",
		entry.Path, entry.Type)
	return nil
}

// disableAudit is used to disable an existing audit backend
func (c *Core) disableAudit(path string) error {
	c.audit.Lock()
	defer c.audit.Unlock()

	// Ensure we end the path in a slash
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	// Remove the entry from the mount table
	newTable := c.audit.Clone()
	found := newTable.Remove(path)

	// Ensure there was a match
	if !found {
		return fmt.Errorf("no matching backend")
	}

	// Update the audit table
	if err := c.persistAudit(newTable); err != nil {
		return errors.New("failed to update audit table")
	}
	c.audit = newTable

	// Unmount the backend
	c.auditBroker.Deregister(path)
	c.logger.Printf("[INFO] core: disabled audit backend '%s'", path)
	return nil
}

// loadAudits is invoked as part of postUnseal to load the audit table
func (c *Core) loadAudits() error {
	// Load the existing audit table
	raw, err := c.barrier.Get(coreAuditConfigPath)
	if err != nil {
		c.logger.Printf("[ERR] core: failed to read audit table: %v", err)
		return loadAuditFailed
	}
	if raw != nil {
		c.audit = &MountTable{}
		if err := json.Unmarshal(raw.Value, c.audit); err != nil {
			c.logger.Printf("[ERR] core: failed to decode audit table: %v", err)
			return loadAuditFailed
		}
	}

	// Done if we have restored the audit table
	if c.audit != nil {
		return nil
	}

	// Create and persist the default audit table
	c.audit = defaultAuditTable()
	if err := c.persistAudit(c.audit); err != nil {
		return loadAuditFailed
	}
	return nil
}

// persistAudit is used to persist the audit table after modification
func (c *Core) persistAudit(table *MountTable) error {
	// Marshal the table
	raw, err := json.Marshal(table)
	if err != nil {
		c.logger.Printf("[ERR] core: failed to encode audit table: %v", err)
		return err
	}

	// Create an entry
	entry := &Entry{
		Key:   coreAuditConfigPath,
		Value: raw,
	}

	// Write to the physical backend
	if err := c.barrier.Put(entry); err != nil {
		c.logger.Printf("[ERR] core: failed to persist audit table: %v", err)
		return err
	}
	return nil
}

// setupAudit is invoked after we've loaded the audit able to
// initialize the audit backends
func (c *Core) setupAudits() error {
	broker := NewAuditBroker(c.logger)
	for _, entry := range c.audit.Entries {
		// Initialize the backend
		audit, err := c.newAuditBackend(entry.Type, entry.Options)
		if err != nil {
			c.logger.Printf(
				"[ERR] core: failed to create audit entry %#v: %v",
				entry, err)
			return loadAuditFailed
		}

		// Create a barrier view using the UUID
		view := NewBarrierView(c.barrier, auditBarrierPrefix+entry.UUID+"/")

		// Mount the backend
		broker.Register(entry.Path, audit, view)
	}
	c.auditBroker = broker
	return nil
}

// teardownAudit is used before we seal the vault to reset the audit
// backends to their unloaded state. This is reversed by loadAudits.
func (c *Core) teardownAudits() error {
	c.audit = nil
	c.auditBroker = nil
	return nil
}

// newAuditBackend is used to create and configure a new audit backend by name
func (c *Core) newAuditBackend(t string, conf map[string]string) (audit.Backend, error) {
	f, ok := c.auditBackends[t]
	if !ok {
		return nil, fmt.Errorf("unknown backend type: %s", t)
	}
	return f(conf)
}

// defaultAuditTable creates a default audit table
func defaultAuditTable() *MountTable {
	table := &MountTable{}
	return table
}

type backendEntry struct {
	backend audit.Backend
	view    *BarrierView
}

// AuditBroker is used to provide a single ingest interface to auditable
// events given that multiple backends may be configured.
type AuditBroker struct {
	l        sync.RWMutex
	backends map[string]backendEntry
	logger   *log.Logger
}

// NewAuditBroker creates a new audit broker
func NewAuditBroker(log *log.Logger) *AuditBroker {
	b := &AuditBroker{
		backends: make(map[string]backendEntry),
		logger:   log,
	}
	return b
}

// Register is used to add new audit backend to the broker
func (a *AuditBroker) Register(name string, b audit.Backend, v *BarrierView) {
	a.l.Lock()
	defer a.l.Unlock()
	a.backends[name] = backendEntry{
		backend: b,
		view:    v,
	}
}

// Deregister is used to remove an audit backend from the broker
func (a *AuditBroker) Deregister(name string) {
	a.l.Lock()
	defer a.l.Unlock()
	delete(a.backends, name)
}

// IsRegistered is used to check if a given audit backend is registered
func (a *AuditBroker) IsRegistered(name string) bool {
	a.l.RLock()
	defer a.l.RUnlock()
	_, ok := a.backends[name]
	return ok
}

// LogRequest is used to ensure all the audit backends have an opportunity to
// log the given request and that *at least one* succeeds.
func (a *AuditBroker) LogRequest(auth *logical.Auth, req *logical.Request) error {
	defer metrics.MeasureSince([]string{"audit", "log_request"}, time.Now())
	a.l.RLock()
	defer a.l.RUnlock()

	// Ensure at least one backend logs
	anyLogged := false
	for name, be := range a.backends {
		start := time.Now()
		err := be.backend.LogRequest(auth, req)
		metrics.MeasureSince([]string{"audit", name, "log_request"}, start)
		if err != nil {
			a.logger.Printf("[ERR] audit: backend '%s' failed to log request: %v", name, err)
		} else {
			anyLogged = true
		}
	}
	if !anyLogged && len(a.backends) > 0 {
		return fmt.Errorf("no audit backend succeeded in logging the request")
	}
	return nil
}

// LogResponse is used to ensure all the audit backends have an opportunity to
// log the given response and that *at least one* succeeds.
func (a *AuditBroker) LogResponse(auth *logical.Auth, req *logical.Request,
	resp *logical.Response, err error) error {
	defer metrics.MeasureSince([]string{"audit", "log_response"}, time.Now())
	a.l.RLock()
	defer a.l.RUnlock()

	// Ensure at least one backend logs
	anyLogged := false
	for name, be := range a.backends {
		start := time.Now()
		err := be.backend.LogResponse(auth, req, resp, err)
		metrics.MeasureSince([]string{"audit", name, "log_response"}, start)
		if err != nil {
			a.logger.Printf("[ERR] audit: backend '%s' failed to log response: %v", name, err)
		} else {
			anyLogged = true
		}
	}
	if !anyLogged && len(a.backends) > 0 {
		return fmt.Errorf("no audit backend succeeded in logging the response")
	}
	return nil
}

func (a *AuditBroker) ServeHTTP(h http.Handler, w http.ResponseWriter, r *http.Request) {
	reqStart := time.Now()

	tee := logical.NewTeeResponseWriter(w)
	body := &logical.TeeReadCloser{r.Body, bytes.Buffer{}}
	r.Body = body

	h.ServeHTTP(tee, r)
	tee.Duration = time.Since(reqStart)

	defer metrics.MeasureSince([]string{"audit", "log_http_request"}, time.Now())
	a.l.RLock()
	defer a.l.RUnlock()

	// Ensure at least one backend logs
	anyLogged := false
	for name, be := range a.backends {
		start := time.Now()
		err := be.backend.LogHTTPRequest(r, tee)

		metrics.MeasureSince([]string{"audit", name, "log_http_request`"}, start)
		if err != nil {
			a.logger.Printf("[ERR] audit: backend '%s' failed to log http request: %v", name, err)
		} else {
			anyLogged = true
		}
	}
	if !anyLogged && len(a.backends) > 0 {
		a.logger.Print("no audit backend succeeded in logging the http request")
	}
}
