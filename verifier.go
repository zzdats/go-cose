// Copyright 2021 SIA ZZ Dats. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"math/big"
)

// Verifier is a public key container for verifying COSE signatures.
type Verifier struct {
	publicKey crypto.PublicKey
	alg       *algorithm
}

// NewVerifier creates a new verifier from a public key and algorithm.
func NewVerifier(alg Algorithm, key crypto.PublicKey) (*Verifier, error) {
	if key == nil {
		return nil, errors.New("key can not be nil")
	}

	a := getAlg(string(alg))
	if a == nil || a.Type == algorithmTypeUnsupported {
		return nil, ErrUnsupportedAlgorithm
	}

	switch k := key.(type) {
	case *rsa.PublicKey:
		if a.Type != algorithmTypeKeyRSA {
			return nil, ErrAlgorithmNotMatchKey
		}
		if a.MinKeySize > 0 && a.MinKeySize > k.Size()*8 {
			return nil, ErrMinKeySize{a.MinKeySize}
		}
	case *ecdsa.PublicKey:
		if a.Type != algorithmTypeKeyECDSA {
			return nil, ErrAlgorithmNotMatchKey
		}
		if a.KeyEllipticCurve.Params().BitSize != k.Curve.Params().BitSize {
			return nil, ErrInvalidEllipticCurve
		}
	case ed25519.PublicKey:
		if a.Type != algorithmTypeKeyED25519 {
			return nil, ErrAlgorithmNotMatchKey
		}
	default:
		return nil, ErrUnsupportedKeyType
	}

	return &Verifier{
		publicKey: key,
		alg:       a,
	}, nil
}

// GetHash returns the hash algorithm used by the verifier.
func (v *Verifier) GetHash() crypto.Hash {
	return v.alg.Hash
}

// Verify verifies a COSE signature.
func (v *Verifier) Verify(digest, sig []byte) error {
	hash := v.GetHash()
	// calculate the hash of the message, if the algorithm requires it
	if hash > 0 {
		if !hash.Available() {
			return ErrUnavailableHashAlgorithm
		}

		h := hash.New()
		_, _ = h.Write(digest)
		digest = h.Sum(nil)
	}

	switch key := v.publicKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPSS(key, hash, digest, sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hash,
		})
		if err == rsa.ErrVerification {
			return ErrVerification
		} else {
			return err
		}
	case *ecdsa.PublicKey:
		keySize := curveByteSize(v.alg.KeyEllipticCurve)
		if len(sig) != keySize*2 {
			return ErrVerification
		}

		r := big.NewInt(0).SetBytes(sig[:keySize])
		s := big.NewInt(0).SetBytes(sig[keySize:])

		if !ecdsa.Verify(key, digest, r, s) {
			return ErrVerification
		} else {
			return nil
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(key, digest, sig) {
			return ErrVerification
		} else {
			return nil
		}
	}
	return ErrUnsupportedKeyType
}
