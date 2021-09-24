// Copyright 2021 SIA ZZ Dats. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cose

import "errors"

const (
	HeaderAlgorithm        = "alg"
	HeaderCritical         = "crit"
	HeaderContentType      = "content type"
	HeaderKeyID            = "kid"
	HeaderIV               = "IV"
	HeaderPartialIV        = "Partial IV"
	HeaderCounterSignature = "counter signature"
)

// Headers represents COSE protected and unprotected headers.
type Headers struct {
	protected   map[interface{}]interface{}
	unprotected map[interface{}]interface{}
}

// NewHeaders creates a new Headers instance.
func NewHeaders() *Headers {
	return &Headers{
		protected:   make(map[interface{}]interface{}),
		unprotected: make(map[interface{}]interface{}),
	}
}

// MergeHeaders merges the given headers into the new Headers instance.
func MergeHeaders(h1, h2 *Headers) *Headers {
	h := NewHeaders()
	h.Merge(h1)
	h.Merge(h2)

	return h
}

// Merge merges the given headers into the current headers.
func (h *Headers) Merge(other *Headers) {
	for k, v := range other.protected {
		h.protected[k] = v
	}
	for k, v := range other.unprotected {
		// Skip headers that are already set in protected headers
		if _, ok := h.protected[k]; ok {
			continue
		}
		h.unprotected[k] = v
	}
}

func getCommonHeader(key string) int64 {
	switch key {
	case HeaderAlgorithm:
		return 1
	case HeaderCritical:
		return 2
	case HeaderContentType:
		return 3
	case HeaderKeyID:
		return 4
	case HeaderIV:
		return 5
	case HeaderPartialIV:
		return 6
	case HeaderCounterSignature:
		return 7
	default:
		return 0
	}
}

// SetProtected sets the header with the given key in protected headers.
func (h *Headers) SetProtected(key, value interface{}) error {
	switch label := key.(type) {
	case string:
		if k := getCommonHeader(label); k != 0 {
			return h.SetProtected(k, value)
		}
		h.protected[key] = value
	case int:
		return h.SetProtected(int64(label), value)
	case int64:
		// Reslove alg value
		if label == 1 {
			if alg, ok := value.(string); ok {
				a := getAlg(alg)
				if a != nil {
					value = a.Value
				}
			}
		}
		h.protected[key] = value
	default:
		return errors.New("invalid key type")
	}
	return nil
}

// GetProtected returns the header with the given key from protected headers.
func (h *Headers) GetProtected(key interface{}) (interface{}, error) {
	switch label := key.(type) {
	case string:
		if k := getCommonHeader(label); k != 0 {
			return h.GetProtected(k)
		}
		return h.protected[label], nil
	case int:
		return h.GetProtected(int64(label))
	case int64:
		// Resolve algorithm value
		if label == 1 {
			value := h.protected[label]
			var a *algorithm
			switch v := value.(type) {
			case int:
				a = getAlgByValue(int64(v))
			case int64:
				a = getAlgByValue(v)
			}
			if a != nil {
				return a.Name, nil
			}
		}
		return h.protected[label], nil
	default:
		return nil, errors.New("invalid key type")
	}
}

// Set sets the header with the given key in unprotected headers.
// `alg` and `crit` will always be set in protected headers.
func (h *Headers) Set(key, value interface{}) error {
	switch label := key.(type) {
	case string:
		if k := getCommonHeader(label); k != 0 {
			return h.Set(k, value)
		}
		h.unprotected[label] = value
	case int:
		return h.Set(int64(label), value)
	case int64:
		// alg and crit MUST be set in protected headers
		if label == 1 || label == 2 {
			return h.SetProtected(label, value)
		}
		h.unprotected[label] = value
	default:
		return errors.New("invalid key type")
	}
	return nil
}

// Get returns the header with the given key from both protected and unprotected headers,
// prioritizing protected headers.
func (h *Headers) Get(key interface{}) (interface{}, error) {
	if v, err := h.GetProtected(key); err != nil {
		return nil, err
	} else if v != nil {
		return v, nil
	}
	switch label := key.(type) {
	case string:
		if k := getCommonHeader(label); k != 0 {
			return h.Get(k)
		}
		return h.unprotected[key], nil
	case int:
		return h.Get(int64(label))
	case int64:
		return h.unprotected[key], nil
	default:
		return nil, errors.New("invalid key type")
	}
}

// Delete removes the header with the given key from protected and unprotected headers.
func (h *Headers) Delete(key interface{}) {
	switch label := key.(type) {
	case string:
		if k := getCommonHeader(label); k != 0 {
			key = k
		}
	case int:
		key = int64(label)
	}
	delete(h.protected, key)
	delete(h.unprotected, key)
}
