// Copyright 2021 SIA ZZ Dats. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cose

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func signAndVerify(t *testing.T, signer *Signer, verifier *Verifier, data []byte) {
	signature, err := signer.Sign(rand.Reader, data)
	require.NoError(t, err)

	err = verifier.Verify(data, signature)
	require.NoError(t, err)
}

func TestSigner_MinRSAKeyLength(t *testing.T) {
	signer, err := NewSigner(AlgorithmPS512, getPrivateKey(t, "rsa1024"))
	assert.ErrorIs(t, err, ErrMinKeySize{2048})
	assert.Nil(t, signer)
}

func TestSigner_PS512InvalidKey(t *testing.T) {
	signer, err := NewSigner(AlgorithmPS512, getPrivateKey(t, "ecdsa256"))
	assert.ErrorIs(t, err, ErrAlgorithmNotMatchKey)
	assert.Nil(t, signer)
}

func TestSigner_SignPS256(t *testing.T) {
	signer, err := NewSigner(AlgorithmPS256, getPrivateKey(t, "rsa2048"))
	require.NoError(t, err)

	verifier, _ := signer.ToVerifier()
	signAndVerify(t, signer, verifier, []byte("test"))
}

func TestSigner_SignPS384(t *testing.T) {
	signer, err := NewSigner(AlgorithmPS384, getPrivateKey(t, "rsa2048"))
	require.NoError(t, err)

	verifier, _ := signer.ToVerifier()
	signAndVerify(t, signer, verifier, []byte("test"))
}

func TestSigner_SignPS512(t *testing.T) {
	signer, err := NewSigner(AlgorithmPS512, getPrivateKey(t, "rsa2048"))
	require.NoError(t, err)

	verifier, _ := signer.ToVerifier()
	signAndVerify(t, signer, verifier, []byte("test"))
}

func TestSigner_ES256InvalidKey(t *testing.T) {
	signer, err := NewSigner(AlgorithmES256, getPrivateKey(t, "rsa2048"))
	assert.ErrorIs(t, err, ErrAlgorithmNotMatchKey)
	assert.Nil(t, signer)
}

func TestSigner_SignES256(t *testing.T) {
	signer, err := NewSigner(AlgorithmES256, getPrivateKey(t, "ecdsa256"))
	require.NoError(t, err)

	verifier, _ := signer.ToVerifier()
	signAndVerify(t, signer, verifier, []byte("test"))
}

func TestSigner_InvalidEllipticCurve(t *testing.T) {
	signer, err := NewSigner(AlgorithmES256, getPrivateKey(t, "ecdsa384"))
	assert.ErrorIs(t, err, ErrInvalidEllipticCurve)
	assert.Nil(t, signer)
}

func TestSigner_SignES384(t *testing.T) {
	signer, err := NewSigner(AlgorithmES384, getPrivateKey(t, "ecdsa384"))
	require.NoError(t, err)

	verifier, _ := signer.ToVerifier()
	signAndVerify(t, signer, verifier, []byte("test"))
}

func TestSigner_SignES512(t *testing.T) {
	signer, err := NewSigner(AlgorithmES512, getPrivateKey(t, "ecdsa521"))
	require.NoError(t, err)

	verifier, _ := signer.ToVerifier()
	signAndVerify(t, signer, verifier, []byte("test"))
}

func TestSigner_EdDSAInvalidKey(t *testing.T) {
	signer, err := NewSigner(AlgorithmPS256, getPrivateKey(t, "ed25519"))
	assert.ErrorIs(t, err, ErrAlgorithmNotMatchKey)
	assert.Nil(t, signer)
}

func TestSigner_SignEdDSA(t *testing.T) {
	signer, err := NewSigner(AlgorithmEdDSA, getPrivateKey(t, "ed25519"))
	require.NoError(t, err)

	verifier, _ := signer.ToVerifier()
	signAndVerify(t, signer, verifier, []byte("test"))
}

func TestSigner_SignNilSigner(t *testing.T) {
	signer, err := NewSigner(AlgorithmPS512, nil)
	assert.Error(t, err, "key can not be nil")
	assert.Nil(t, signer)
}

func TestSigner_SignUnsupportedAlgorithm(t *testing.T) {
	signer, err := NewSigner(Algorithm("unsupported"), getPrivateKey(t, "rsa2048"))
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
	assert.Nil(t, signer)
}

func TestSigner_GetHeaders(t *testing.T) {
	tests := []struct {
		name string
		alg  Algorithm
		key  string
	}{
		{name: "PS256", alg: AlgorithmPS256, key: "rsa2048"},
		{name: "PS384", alg: AlgorithmPS384, key: "rsa2048"},
		{name: "PS512", alg: AlgorithmPS512, key: "rsa2048"},
		{name: "ES256", alg: AlgorithmES256, key: "ecdsa256"},
		{name: "ES384", alg: AlgorithmES384, key: "ecdsa384"},
		{name: "ES512", alg: AlgorithmES512, key: "ecdsa521"},
		{name: "EdDSA", alg: AlgorithmEdDSA, key: "ed25519"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewSigner(tt.alg, getPrivateKey(t, tt.key))
			require.NoError(t, err)

			headers, err := signer.GetHeaders()
			require.NoError(t, err)

			alg, err := headers.GetProtected(HeaderAlgorithm)
			require.NoError(t, err)

			assert.Equal(t, string(tt.alg), alg)
		})
	}
}
