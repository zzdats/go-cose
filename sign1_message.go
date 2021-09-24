// Copyright 2021 SIA ZZ Dats. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cose

// Sign1Message represents a COSE_Sign1 message.
type Sign1Message struct {
	Headers *Headers
	Signer  *Signer
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
	m := &Sign1Message{
		Headers: NewHeaders(),
		content: c.Payload,
	}
	for k, v := range c.Unprotected {
		if err := m.Headers.Set(k, v); err != nil {
			return nil, err
		}
	}

	var prot map[interface{}]interface{}
	if err := e.decMode.Unmarshal(c.Protected, &prot); err != nil {
		return nil, err
	}
	for k, v := range prot {
		if err := m.Headers.SetProtected(k, v); err != nil {
			return nil, err
		}
	}
	return m, nil
}
