// Copyright 2021 SIA ZZ Dats. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cose

import (
	"crypto/rand"
	"crypto/rsa"
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
	msg.Signer, err = NewSigner(AlgorithmPS256, key)
	require.NoError(t, err)

	b, err := StdEncoding.Encode(msg)
	require.NoError(t, err)
	require.NotEmpty(t, b)

	// Decode COSE_Sign1 message
	dec, err := StdEncoding.Decode(b, &Config{
		GetVerifiers: func(headers *Headers) ([]*Verifier, error) {
			verifier, err := msg.Signer.ToVerifier()
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
	msg.Signer, err = NewSigner(AlgorithmPS256, key)
	require.NoError(t, err)

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
