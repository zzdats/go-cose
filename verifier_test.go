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

func TestVerifier_ES256InvalidSignatureHashSize(t *testing.T) {
	signer, err := NewSigner(AlgorithmPS512, getPrivateKey(t, "rsa2048"))
	require.NoError(t, err)

	signature, err := signer.Sign(rand.Reader, []byte("test"))
	require.NoError(t, err)

	verifier, err := NewVerifier(AlgorithmES256, getPublicKey(t, "ecdsa256"))
	require.NoError(t, err)

	err = verifier.Verify([]byte("test"), signature)
	require.Error(t, err, ErrVerification)
}

func TestVerifier_ES256InvalidSignature(t *testing.T) {
	signer, err := NewSigner(AlgorithmES256, getPrivateKey(t, "ecdsa256"))
	require.NoError(t, err)

	signature, err := signer.Sign(rand.Reader, []byte("test"))
	require.NoError(t, err)

	verifier, err := NewVerifier(AlgorithmES256, getPublicKey(t, "ecdsa256-2"))
	require.NoError(t, err)

	err = verifier.Verify([]byte("test"), signature)
	require.Error(t, err, ErrVerification)
}

func TestVerifier_PS256InvalidSignature(t *testing.T) {
	signer, err := NewSigner(AlgorithmES256, getPrivateKey(t, "ecdsa256"))
	require.NoError(t, err)

	signature, err := signer.Sign(rand.Reader, []byte("test"))
	require.NoError(t, err)

	verifier, err := NewVerifier(AlgorithmPS512, getPublicKey(t, "rsa2048"))
	require.NoError(t, err)

	err = verifier.Verify([]byte("test"), signature)
	require.Error(t, err, ErrVerification)
}

func TestVerifier_EdDSAInvalidSignature(t *testing.T) {
	signer, err := NewSigner(AlgorithmPS512, getPrivateKey(t, "rsa2048"))
	require.NoError(t, err)

	signature, err := signer.Sign(rand.Reader, []byte("test"))
	require.NoError(t, err)

	verifier, err := NewVerifier(AlgorithmEdDSA, getPublicKey(t, "ed25519"))
	require.NoError(t, err)

	err = verifier.Verify([]byte("test"), signature)
	require.Error(t, err, ErrVerification)
}

func TestVerifier_PS512InvalidKey(t *testing.T) {
	verifier, err := NewVerifier(AlgorithmPS512, getPublicKey(t, "ecdsa256"))
	assert.ErrorIs(t, err, ErrAlgorithmNotMatchKey)
	assert.Nil(t, verifier)
}

func TestVerifier_ES256InvalidKey(t *testing.T) {
	verifier, err := NewVerifier(AlgorithmES256, getPublicKey(t, "rsa2048"))
	assert.ErrorIs(t, err, ErrAlgorithmNotMatchKey)
	assert.Nil(t, verifier)
}

func TestVerifier_EdDSAInvalidKey(t *testing.T) {
	verifier, err := NewVerifier(AlgorithmPS256, getPublicKey(t, "ed25519"))
	assert.ErrorIs(t, err, ErrAlgorithmNotMatchKey)
	assert.Nil(t, verifier)
}

func TestVerifier_MinRSAKeyLength(t *testing.T) {
	verifier, err := NewVerifier(AlgorithmPS512, getPublicKey(t, "rsa1024"))
	assert.ErrorIs(t, err, ErrMinKeySize{2048})
	assert.Nil(t, verifier)
}

func TestVerifier_InvalidEllipticCurve(t *testing.T) {
	verifier, err := NewVerifier(AlgorithmES256, getPublicKey(t, "ecdsa384"))
	assert.ErrorIs(t, err, ErrInvalidEllipticCurve)
	assert.Nil(t, verifier)
}
