// Copyright 2021 SIA ZZ Dats. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"

	// Required hashing algorithms
	_ "crypto/sha256"
)

// Signer represents a signer with a private key and algorithm
type Signer struct {
	Headers    *Headers
	privateKey crypto.PrivateKey
	alg        *algorithm
}

// NewSigner creates a new signer with a private key and algorithm
func NewSigner(alg Algorithm, key crypto.PrivateKey) (*Signer, error) {
	if key == nil {
		return nil, errors.New("key can not be nil")
	}

	a := getAlg(string(alg))
	if a == nil || a.Type == algorithmTypeUnsupported {
		return nil, ErrUnsupportedAlgorithm
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		if a.Type != algorithmTypeKeyRSA {
			return nil, ErrAlgorithmNotMatchKey
		}
		if a.MinKeySize > 0 && a.MinKeySize > k.Size()*8 {
			return nil, ErrMinKeySize{a.MinKeySize}
		}
	case *ecdsa.PrivateKey:
		if a.Type != algorithmTypeKeyECDSA {
			return nil, ErrAlgorithmNotMatchKey
		}
		if a.KeyEllipticCurve.Params().BitSize != k.Curve.Params().BitSize {
			return nil, ErrInvalidEllipticCurve
		}
	case ed25519.PrivateKey:
		if a.Type != algorithmTypeKeyED25519 {
			return nil, ErrAlgorithmNotMatchKey
		}
	default:
		return nil, ErrUnsupportedKeyType
	}

	return &Signer{
		Headers:    NewHeaders(),
		privateKey: key,
		alg:        a,
	}, nil
}

// GetHash returns the hash algorithm of the signer
func (s *Signer) GetHash() crypto.Hash {
	return s.alg.Hash
}

// GetHeader returns the headers for message signature
func (s *Signer) GetHeaders() (*Headers, error) {
	h := NewHeaders()
	if err := h.SetProtected(HeaderAlgorithm, s.alg.Value); err != nil {
		return nil, err
	}

	return MergeHeaders(s.Headers, h), nil
}

// ToVerifier returns the public key verifier for the signer
func (s *Signer) ToVerifier() (*Verifier, error) {
	switch k := s.privateKey.(type) {
	case *rsa.PrivateKey:
		return NewVerifier(Algorithm(s.alg.Name), k.Public())
	case *ecdsa.PrivateKey:
		return NewVerifier(Algorithm(s.alg.Name), k.Public())
	case ed25519.PrivateKey:
		return NewVerifier(Algorithm(s.alg.Name), k.Public())
	}
	return nil, ErrUnsupportedKeyType
}

// Sign signs the message with the private key using the algorithm
func (s *Signer) Sign(rand io.Reader, digest []byte) ([]byte, error) {
	hash := s.GetHash()
	// calculate the hash of the message, if the algorithm requires it
	if hash > 0 {
		if !hash.Available() {
			return nil, ErrUnavailableHashAlgorithm
		}

		h := hash.New()
		_, _ = h.Write(digest)
		digest = h.Sum(nil)
	}

	switch key := s.privateKey.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPSS(rand, key, hash, digest, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hash,
		})
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand, key, digest)
		if err != nil {
			return nil, err
		}

		sBits, rBits, dBits := len(s.Bits()), len(r.Bits()), len(key.D.Bits())
		if !(approxEqual(sBits, rBits) && approxEqual(sBits, dBits) && approxEqual(rBits, dBits)) {
			return nil, fmt.Errorf("s %d and r %d does not approximately match key D %d", sBits, rBits, dBits)
		}

		n := curveByteSize(key.Curve)
		sig := make([]byte, 0, n*2)
		sig = append(sig, i2osp(r, n)...)
		sig = append(sig, i2osp(s, n)...)

		return sig, nil
	case ed25519.PrivateKey:
		return key.Sign(rand, digest, crypto.Hash(0))
	default:
		return nil, ErrUnsupportedKeyType
	}
}

// curveByteSize returns the curve key size in bytes with padding
func curveByteSize(curve elliptic.Curve) int {
	bitSize := curve.Params().BitSize
	s := bitSize / 8
	// add a byte for padding
	if bitSize%8 > 0 {
		s++
	}
	return s
}

// i2osp "Integer-to-Octet-String" converts a nonnegative integer to
// an octet string of a specified length
func i2osp(b *big.Int, n int) []byte {
	var (
		octetString     = b.Bytes()
		octetStringSize = len(octetString)
		result          = make([]byte, n)
	)
	if !(b.Sign() == 0 || b.Sign() == 1) {
		panic("I2OSP error: integer must be zero or positive")
	}
	if n == 0 || octetStringSize > n {
		panic("I2OSP error: integer too large")
	}

	subtle.ConstantTimeCopy(1, result[:n-octetStringSize], result[:n-octetStringSize])
	subtle.ConstantTimeCopy(1, result[n-octetStringSize:], octetString)
	return result
}

// approxEquals returns a bool of whether x and y are equal within delta 1
func approxEqual(x, y int) bool {
	if x > y {
		return uint(x-y) <= 1
	}
	return uint(y-x) <= 1
}
