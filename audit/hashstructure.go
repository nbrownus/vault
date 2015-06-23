package audit

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"

	"github.com/hashicorp/vault/logical"
	"github.com/mitchellh/copystructure"
	"github.com/mitchellh/reflectwalk"
	"net/http"
	"bytes"
)

// Hash will hash the given type. This has built-in support for auth,
// requests, and responses. If it is a type that isn't recognized, then
// it will be passed through.
//
// The structure is modified in-place.
func Hash(raw interface{}) error {
	fn := HashSHA1("")

	switch s := raw.(type) {
	case *logical.Auth:
		if s == nil {
			return nil
		}
		if s.ClientToken != "" {
			token, err := fn(s.ClientToken)
			if err != nil {
				return err
			}

			s.ClientToken = token
		}
	case *logical.Request:
		if s == nil {
			return nil
		}
		if s.Auth != nil {
			if err := Hash(s.Auth); err != nil {
				return err
			}
		}

		data, err := HashStructure(s.Data, fn)
		if err != nil {
			return err
		}

		s.Data = data.(map[string]interface{})
	case *logical.Response:
		if s == nil {
			return nil
		}
		if s.Auth != nil {
			if err := Hash(s.Auth); err != nil {
				return err
			}
		}

		data, err := HashStructure(s.Data, fn)
		if err != nil {
			return err
		}

		s.Data = data.(map[string]interface{})
	case *http.Request:
		if s == nil {
			return nil
		}

		if s.Body != nil {
			body, err := fn(s.Body.(*logical.TeeReadCloser).Bytes.String())
			if err != nil {
				return err
			}
			s.Body.(*logical.TeeReadCloser).Bytes = *bytes.NewBufferString(body)
		}

		if s.Header != nil {
			if err := Hash(s.Header); err != nil {
				return err
			}
		}
	case *logical.TeeResponseWriter:
		if s == nil {
			return nil
		}

		if s.RawHeader != nil {
			if err := Hash(s.RawHeader); err != nil {
				return err
			}
		}

		body, err := fn(s.Body.String())
		if err != nil {
			return err
		}
		s.Body = *bytes.NewBufferString(body)
	case http.Header:
		if s == nil {
			return nil
		}

		if s["x-vault-token"] != nil {
			token, err := HashStructure(s["x-vault-token"], fn)
			if err != nil {
				return err
			}
			s["x-vault-token"] = token.([]string)
		}

		if s["cookie"] != nil {
			cookie, err := HashStructure(s["cookie"], fn)
			if err != nil {
				return err
			}
			s["cookie"] = cookie.([]string)
		}
	}

	return nil
}

// HashStructure takes an interface and hashes all the values within
// the structure. Only _values_ are hashed: keys of objects are not.
//
// For the HashCallback, see the built-in HashCallbacks below.
func HashStructure(s interface{}, cb HashCallback) (interface{}, error) {
	s, err := copystructure.Copy(s)
	if err != nil {
		return nil, err
	}

	walker := &hashWalker{Callback: cb}
	if err := reflectwalk.Walk(s, walker); err != nil {
		return nil, err
	}

	return s, nil
}

// HashCallback is the callback called for HashStructure to hash
// a value.
type HashCallback func(string) (string, error)

// HashSHA1 returns a HashCallback that hashes data with SHA1 and
// with an optional salt. If salt is a blank string, no salt is used.
func HashSHA1(salt string) HashCallback {
	return func(v string) (string, error) {
		hashed := sha1.Sum([]byte(v + salt))
		return "sha1:" + hex.EncodeToString(hashed[:]), nil
	}
}

// hashWalker implements interfaces for the reflectwalk package
// (github.com/mitchellh/reflectwalk) that can be used to automatically
// replace primitives with a hashed value.
type hashWalker struct {
	// Callback is the function to call with the primitive that is
	// to be hashed. If there is an error, walking will be halted
	// immediately and the error returned.
	Callback HashCallback

	key         []string
	lastValue   reflect.Value
	loc         reflectwalk.Location
	cs          []reflect.Value
	csKey       []reflect.Value
	csData      interface{}
	sliceIndex  int
	unknownKeys []string
}

func (w *hashWalker) Enter(loc reflectwalk.Location) error {
	w.loc = loc
	return nil
}

func (w *hashWalker) Exit(loc reflectwalk.Location) error {
	w.loc = reflectwalk.None

	switch loc {
	case reflectwalk.Map:
		w.cs = w.cs[:len(w.cs)-1]
	case reflectwalk.MapValue:
		w.key = w.key[:len(w.key)-1]
		w.csKey = w.csKey[:len(w.csKey)-1]
	case reflectwalk.Slice:
		w.cs = w.cs[:len(w.cs)-1]
	case reflectwalk.SliceElem:
		w.csKey = w.csKey[:len(w.csKey)-1]
	}

	return nil
}

func (w *hashWalker) Map(m reflect.Value) error {
	w.cs = append(w.cs, m)
	return nil
}

func (w *hashWalker) MapElem(m, k, v reflect.Value) error {
	w.csData = k
	w.csKey = append(w.csKey, k)
	w.key = append(w.key, k.String())
	w.lastValue = v
	return nil
}

func (w *hashWalker) Slice(s reflect.Value) error {
	w.cs = append(w.cs, s)
	return nil
}

func (w *hashWalker) SliceElem(i int, elem reflect.Value) error {
	w.csKey = append(w.csKey, reflect.ValueOf(i))
	w.sliceIndex = i
	return nil
}

func (w *hashWalker) Primitive(v reflect.Value) error {
	if w.Callback == nil {
		return nil
	}

	// We don't touch map keys
	if w.loc == reflectwalk.MapKey {
		return nil
	}

	setV := v

	// We only care about strings
	if v.Kind() == reflect.Interface {
		setV = v
		v = v.Elem()
	}
	if v.Kind() != reflect.String {
		return nil
	}

	replaceVal, err := w.Callback(v.Interface().(string))
	if err != nil {
		return fmt.Errorf("Error hashing value: %s", err)
	}

	resultVal := reflect.ValueOf(replaceVal)
	switch w.loc {
	case reflectwalk.MapKey:
		m := w.cs[len(w.cs)-1]

		// Delete the old value
		var zero reflect.Value
		m.SetMapIndex(w.csData.(reflect.Value), zero)

		// Set the new key with the existing value
		m.SetMapIndex(resultVal, w.lastValue)

		// Set the key to be the new key
		w.csData = resultVal
	case reflectwalk.MapValue:
		// If we're in a map, then the only way to set a map value is
		// to set it directly.
		m := w.cs[len(w.cs)-1]
		mk := w.csData.(reflect.Value)
		m.SetMapIndex(mk, resultVal)
	default:
		// Otherwise, we should be addressable
		setV.Set(resultVal)
	}

	return nil
}

func (w *hashWalker) removeCurrent() {
	// Append the key to the unknown keys
	w.unknownKeys = append(w.unknownKeys, strings.Join(w.key, "."))

	for i := 1; i <= len(w.cs); i++ {
		c := w.cs[len(w.cs)-i]
		switch c.Kind() {
		case reflect.Map:
			// Zero value so that we delete the map key
			var val reflect.Value

			// Get the key and delete it
			k := w.csData.(reflect.Value)
			c.SetMapIndex(k, val)
			return
		}
	}

	panic("No container found for removeCurrent")
}

func (w *hashWalker) replaceCurrent(v reflect.Value) {
	c := w.cs[len(w.cs)-2]
	switch c.Kind() {
	case reflect.Map:
		// Get the key and delete it
		k := w.csKey[len(w.csKey)-1]
		c.SetMapIndex(k, v)
	}
}
