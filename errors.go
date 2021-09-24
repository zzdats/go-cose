// Copyright 2021 SIA ZZ Dats. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cose

import (
	"errors"
	"fmt"
)

var (
	// ErrUnsupportedKeyType represents an error when a key type is not supported.
	ErrUnsupportedKeyType = errors.New("unsupported key type")
	// ErrUnavailableHashAlgorithm represents an error when a hash algorithm is not available.
	ErrUnavailableHashAlgorithm = errors.New("hash algorithm unavailable")
	// ErrUnsupportedAlgorithm represents an error when an algorithm is not supported.
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
	// ErrAlgorithmNotMatchKey represents an error when an algorithm does not match the key type.
	ErrAlgorithmNotMatchKey = errors.New("algorithm does not match key type")
	// ErrInvalidEllipticCurve represents an error when an elliptic curve size does not match the key.
	ErrInvalidEllipticCurve = errors.New("invalid elliptic curve")
	// ErrVerification represents a failure to verify a signature.
	ErrVerification = errors.New("verification error")
)

// ErrMinKeySize represents an error when a key is too small.
type ErrMinKeySize struct {
	Size int
}

func (e ErrMinKeySize) Error() string {
	return fmt.Sprintf("key of size %d or larger must be used", e.Size)
}

// ErrUnsupportedMessageTag represents an error when a message tag is not supported.
type ErrUnsupportedMessageTag struct {
	Tag uint64
}

func (e ErrUnsupportedMessageTag) Error() string {
	return fmt.Sprintf("unsupported COSE message tag: %d", e.Tag)
}
