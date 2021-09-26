// Copyright 2021 SIA ZZ Dats. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cose

// Sign1Message represents a COSE_Sign1 message.
type Sign1Message struct {
	Headers *Headers
	signer  *Signer
	content []byte
}

// NewSign1Message creates a new Sign1Message instance.
func NewSign1Message() *Sign1Message {
	return &Sign1Message{
		Headers: NewHeaders(),
	}
}

// GetMessageTag returns the COSE_Sign1 message tag.
func (m *Sign1Message) GetMessageTag() uint64 {
	return MessageTagSign1
}

// GetContent returns the message content.
func (m *Sign1Message) GetContent() []byte {
	return m.content
}

// SetContent sets the message content.
func (m *Sign1Message) SetContent(content []byte) {
	m.content = content
}

// SetSigner sets the signer.
func (m *Sign1Message) SetSigner(signer *Signer) {
	m.signer = signer
}

func (m *Sign1Message) sign(e *Encoding, external []byte) (interface{}, error) {
	sheaders, err := m.signer.GetHeaders()
	if err != nil {
		return nil, err
	}
	h := MergeHeaders(m.Headers, sheaders)

	ph, err := e.marshal(h.protected)
	if err != nil {
		return nil, err
	}

	msg := sign1Message{
		Protected:   ph,
		Unprotected: h.unprotected,
		Payload:     m.GetContent(),
	}
	digest, err := msg.GetDigest(e, external)
	if err != nil {
		return nil, err
	}
	if msg.Signature, err = m.signer.Sign(e.rand, digest); err != nil {
		return nil, err
	}
	return msg, nil
}

type sign1Message struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[interface{}]interface{}
	Payload     []byte
	Signature   []byte
}

func (m *sign1Message) GetDigest(e *Encoding, external []byte) ([]byte, error) {
	return e.marshal([]interface{}{
		"Signature1",
		m.Protected,
		external,
		m.Payload,
	})
}

func newSign1Message(e *Encoding, c *sign1Message) (*Sign1Message, error) {
	h, err := newHeaders(e, c.Protected, c.Unprotected)
	if err != nil {
		return nil, err
	}

	return &Sign1Message{
		Headers: h,
		content: c.Payload,
	}, nil
}
