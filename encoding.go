// Copyright 2021 SIA ZZ Dats. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cose

import (
	"crypto/rand"
	"fmt"
	"io"
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

const (
	// MessageTagUnknown is the tag for unknown messages
	MessageTagUnkown = 0
	// MessageTagEncrypt0 is the tag for encrypt messages without specifid recipients
	MessageTagEncrypt0 = 16
	// MessageTagEncrypt is the tag for encrypt messages with specifid recipients
	MessageTagEncrypt = 96
	// MessageTagSign1 is the tag for signed messages with single signer
	MessageTagSign1 = 18
	// MessageTagSign is the tag for signed messages with multiple signers
	MessageTagSign = 98
	// MessageTagMAC is the tag for MAC messages with specified recipients
	MessageTagMAC = 97
	// MessageTagMAC0 is the tag for MAC messages where recipients are not specified
	MessageTagMAC0 = 17
)

// Encoding is the COSE encoding
type Encoding struct {
	encMode cbor.EncMode
	decMode cbor.DecMode
	rand    io.Reader
}

// Config is the configuration for the COSE encoding
type Config struct {
	// GetVerifiers returns the verifiers for the given message signature
	GetVerifiers func(*Headers) ([]*Verifier, error)
}

var (
	// StdEncoging is the COSE standard encoding
	StdEncoding, stdEncodingErr = NewEncoding()
)

// NewEncoding creates a new COSE encoding
func NewEncoding() (*Encoding, error) {
	enc := &Encoding{
		rand: rand.Reader,
	}
	var err error

	// Initialize the encoder mode
	encOptions := cbor.EncOptions{
		IndefLength: cbor.IndefLengthForbidden,
		Sort:        cbor.SortCanonical,
	}
	if enc.encMode, err = encOptions.EncMode(); err != nil {
		return nil, err
	}

	// Initialize the docoder mode
	tags := cbor.NewTagSet()
	if err = tags.Add(
		cbor.TagOptions{EncTag: cbor.EncTagRequired, DecTag: cbor.DecTagRequired},
		reflect.TypeOf(Sign1Message{}),
		MessageTagSign1,
	); err != nil {
		return nil, err
	}
	decOptions := cbor.DecOptions{
		IndefLength: cbor.IndefLengthForbidden,
		IntDec:      cbor.IntDecConvertSigned,
	}
	if enc.decMode, err = decOptions.DecModeWithTags(tags); err != nil {
		return nil, err
	}

	return enc, nil
}

// EncodeWithExternal encodes the given message with the given external data
func (e *Encoding) EncodeWithExternal(message Message, external []byte) ([]byte, error) {
	var m interface{}
	switch msg := message.(type) {
	case *Sign1Message:
		sheaders, err := msg.Signer.GetHeaders()
		if err != nil {
			return nil, err
		}
		h := MergeHeaders(msg.Headers, sheaders)

		ph, err := e.marshal(h.protected)
		if err != nil {
			return nil, err
		}

		s1m := sign1Message{
			Protected:   ph,
			Unprotected: h.unprotected,
			Payload:     msg.GetContent(),
		}
		digest, err := s1m.GetDigest(e, external)
		if err != nil {
			return nil, err
		}
		if s1m.Signature, err = msg.Signer.Sign(e.rand, digest); err != nil {
			return nil, err
		}

		m = s1m
	default:
		return nil, ErrUnsupportedMessageTag{message.GetMessageTag()}
	}
	return e.encMode.Marshal(cbor.Tag{Number: message.GetMessageTag(), Content: m})
}

// Encode encodes the given message
func (e *Encoding) Encode(message Message) ([]byte, error) {
	return e.EncodeWithExternal(message, []byte{})
}

// DecodeWithExternal decodes the given data with the given external data
func (e *Encoding) DecodeWithExternal(data, external []byte, config *Config) (Message, error) {
	var raw cbor.RawTag
	if err := e.decMode.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	switch raw.Number {
	case MessageTagSign1:
		var c sign1Message
		if err := e.decMode.Unmarshal(raw.Content, &c); err != nil {
			return nil, err
		}

		msg, err := newSign1Message(e, &c)
		if err != nil {
			return nil, err
		}

		var verifiers []*Verifier
		if config != nil {
			verifiers, err = config.GetVerifiers(msg.Headers)
		}

		if err == nil {
			if len(verifiers) == 0 {
				err = ErrVerification
			} else {
				var digest []byte
				digest, err = c.GetDigest(e, external)
				if err == nil {
					var verr error
					for _, v := range verifiers {
						if verr = v.Verify(digest, c.Signature); verr == nil {
							break
						}
					}
					err = verr
				}
			}
		}

		return msg, err
	default:
		return nil, ErrUnsupportedMessageTag{raw.Number}
	}
}

// Decode decodes the given data
func (e *Encoding) Decode(data []byte, config *Config) (Message, error) {
	return e.DecodeWithExternal(data, []byte{}, config)
}

func (e *Encoding) marshal(o interface{}) (b []byte, err error) {
	defer func() {
		// Need to recover from panic
		if r := recover(); r != nil {
			b = nil
			switch x := r.(type) {
			case error:
				err = x
			default:
				err = fmt.Errorf("cbor: %v", x)
			}
		}
	}()
	return e.encMode.Marshal(o)
}

func init() {
	if stdEncodingErr != nil {
		panic(stdEncodingErr)
	}
}
