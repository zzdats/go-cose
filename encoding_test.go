// Copyright 2021 SIA ZZ Dats. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cose

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncoding_Encode(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Encode COSE_Sign1 message
	msg := NewSign1Message()
	msg.SetContent([]byte("test"))
	signer, err := NewSigner(AlgorithmPS256, key)
	require.NoError(t, err)
	msg.SetSigner(signer)

	b, err := StdEncoding.Encode(msg)
	require.NoError(t, err)
	require.NotEmpty(t, b)

	// Decode COSE_Sign1 message
	dec, err := StdEncoding.Decode(b, &Config{
		GetVerifiers: func(headers *Headers) ([]*Verifier, error) {
			verifier, err := signer.ToVerifier()
			if err != nil {
				return nil, err
			}
			return []*Verifier{verifier}, nil
		},
	})
	require.NoError(t, err)
	assert.Equal(t, msg.GetContent(), dec.GetContent())
}

func TestEncoding_DecodeErrorWithoutVerifier(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Encode COSE_Sign1 message
	msg := NewSign1Message()
	msg.SetContent([]byte("test"))
	signer, err := NewSigner(AlgorithmPS256, key)
	require.NoError(t, err)
	msg.SetSigner(signer)

	b, err := StdEncoding.Encode(msg)
	require.NoError(t, err)
	require.NotEmpty(t, b)

	dec, err := StdEncoding.Decode(b, &Config{
		GetVerifiers: func(headers *Headers) ([]*Verifier, error) {
			return nil, nil
		},
	})
	assert.Error(t, err, ErrVerification)
	assert.Equal(t, msg.GetContent(), dec.GetContent())
}

func TestEncoding_EncodeMultipeSigners(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Encode COSE_Sign message
	msg := NewSignMessage()
	msg.SetContent([]byte("test"))
	signer1, err := NewSigner(AlgorithmPS256, key1)
	signer1.Headers.Set(HeaderKeyID, 1)
	require.NoError(t, err)
	msg.AddSigner(signer1)
	signer2, err := NewSigner(AlgorithmPS256, key2)
	signer2.Headers.Set(HeaderKeyID, 2)
	require.NoError(t, err)
	msg.AddSigner(signer2)

	b, err := StdEncoding.Encode(msg)
	require.NoError(t, err)
	require.NotEmpty(t, b)

	// Decode COSE_Sign1 message
	dec, err := StdEncoding.Decode(b, &Config{
		GetVerifiers: func(headers *Headers) ([]*Verifier, error) {
			kid, err := headers.Get(HeaderKeyID)
			if err != nil {
				return nil, err
			}
			if kid.(int64) == 1 {
				verifier, err := signer1.ToVerifier()
				if err != nil {
					return nil, err
				}
				return []*Verifier{verifier}, nil
			} else if kid.(int64) == 2 {
				verifier, err := signer2.ToVerifier()
				if err != nil {
					return nil, err
				}
				return []*Verifier{verifier}, nil
			}
			return nil, fmt.Errorf("unknown kid %v", kid)
		},
	})
	require.NoError(t, err)
	assert.Equal(t, msg.GetContent(), dec.GetContent())
}

func TestEncoding_DecodeInvalidVerifier(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Encode COSE_Sign message
	msg := NewSignMessage()
	msg.SetContent([]byte("test"))
	signer1, err := NewSigner(AlgorithmPS256, key1)
	signer1.Headers.Set(HeaderKeyID, 1)
	require.NoError(t, err)
	msg.AddSigner(signer1)
	signer2, err := NewSigner(AlgorithmPS256, key2)
	signer2.Headers.Set(HeaderKeyID, 2)
	require.NoError(t, err)
	msg.AddSigner(signer2)

	b, err := StdEncoding.Encode(msg)
	require.NoError(t, err)
	require.NotEmpty(t, b)

	// Decode COSE_Sign1 message
	dec, err := StdEncoding.Decode(b, &Config{
		GetVerifiers: func(headers *Headers) ([]*Verifier, error) {
			verifier, err := signer2.ToVerifier()
			if err != nil {
				return nil, err
			}
			return []*Verifier{verifier}, nil
		},
	})
	assert.Error(t, err, ErrVerification)
	assert.Equal(t, msg.GetContent(), dec.GetContent())
}
