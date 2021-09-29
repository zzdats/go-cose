// Copyright 2021 SIA ZZ Dats. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cose

// SignMessage represents a COSE_Sign message.
type SignMessage struct {
	Headers *Headers
	signers []*Signer
	content []byte
}

// NewSignMessage creates a new SignMessage instance.
func NewSignMessage() *SignMessage {
	return &SignMessage{
		Headers: NewHeaders(),
		signers: make([]*Signer, 0),
	}
}

// GetMessageTag returns the COSE_Sign message tag.
func (m *SignMessage) GetMessageTag() uint64 {
	return MessageTagSign
}

// GetContent returns the message content.
func (m *SignMessage) GetContent() []byte {
	return m.content
}

// SetContent sets the message content.
func (m *SignMessage) SetContent(content []byte) {
	m.content = content
}

// AddSigner adds a signer for the message.
func (m *SignMessage) AddSigner(signer *Signer) {
	if signer == nil {
		return
	}
	m.signers = append(m.signers, signer)
}

func (m *SignMessage) sign(e *Encoding, external []byte) (interface{}, error) {
	ph, err := e.marshal(m.Headers.protected)
	if err != nil {
		return nil, err
	}

	msg := signMessage{
		Protected:   ph,
		Unprotected: m.Headers.unprotected,
		Payload:     m.GetContent(),
		Signatures:  make([]*signMessageSignature, len(m.signers)),
	}
	for i, signer := range m.signers {
		sheaders, err := signer.GetHeaders()
		if err != nil {
			return nil, err
		}
		ph, err := e.marshal(sheaders.protected)
		if err != nil {
			return nil, err
		}
		digest, err := msg.GetDigest(e, ph, external)
		if err != nil {
			return nil, err
		}
		msg.Signatures[i] = &signMessageSignature{
			Protected:   ph,
			Unprotected: sheaders.unprotected,
		}
		msg.Signatures[i].Signature, err = signer.Sign(e.rand, digest)
		if err != nil {
			return nil, err
		}
	}
	return msg, nil
}

type signMessageSignature struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[interface{}]interface{}
	Signature   []byte
}

type signMessage struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[interface{}]interface{}
	Payload     []byte
	Signatures  []*signMessageSignature
}

func (m *signMessage) GetDigest(e *Encoding, signerProtected []byte, external []byte) ([]byte, error) {
	return e.marshal([]interface{}{
		"Signature",
		m.Protected,
		signerProtected,
		external,
		m.Payload,
	})
}

func newSignMessage(e *Encoding, c *signMessage) (*SignMessage, error) {
	h, err := newHeaders(e, c.Protected, c.Unprotected)
	if err != nil {
		return nil, err
	}

	return &SignMessage{
		Headers: h,
		content: c.Payload,
	}, nil
}
