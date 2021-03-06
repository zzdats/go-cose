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
	// Verified callback
	Verified func(*Verifier)
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
	if err = tags.Add(
		cbor.TagOptions{EncTag: cbor.EncTagRequired, DecTag: cbor.DecTagRequired},
		reflect.TypeOf(SignMessage{}),
		MessageTagSign,
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
		sm, err := msg.sign(e, external)
		if err != nil {
			return nil, err
		}
		m = sm
	case *SignMessage:
		sm, err := msg.sign(e, external)
		if err != nil {
			return nil, err
		}
		m = sm
	default:
		return nil, ErrUnsupportedMessageTag{message.GetMessageTag()}
	}
	return e.encMode.Marshal(cbor.Tag{Number: message.GetMessageTag(), Content: m})
}

// Encode encodes the given message
func (e *Encoding) Encode(message Message) ([]byte, error) {
	return e.EncodeWithExternal(message, []byte{})
}

func verifySignature(config *Config, headers *Headers, digest, signature []byte) error {
	var err error
	var verifiers []*Verifier
	if config != nil {
		verifiers, err = config.GetVerifiers(headers)
	}

	if err == nil {
		if len(verifiers) == 0 {
			err = ErrVerification
		} else {
			var verr error
			for _, v := range verifiers {
				if verr = v.Verify(digest, signature); verr == nil {
					if config != nil && config.Verified != nil {
						config.Verified(v)
					}
					break
				}
			}
			err = verr
		}
	}
	return err
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

		var digest []byte
		digest, err = c.GetDigest(e, external)
		if err != nil {
			return msg, err
		}

		return msg, verifySignature(config, msg.Headers, digest, c.Signature)
	case MessageTagSign:
		var c signMessage
		if err := e.decMode.Unmarshal(raw.Content, &c); err != nil {
			return nil, err
		}

		msg, err := newSignMessage(e, &c)
		if err != nil {
			return nil, err
		}

		for _, sig := range c.Signatures {
			var digest []byte
			digest, err = c.GetDigest(e, sig.Protected, external)
			if err != nil {
				return msg, err
			}

			sheaders, err := newHeaders(e, sig.Protected, sig.Unprotected)
			if err != nil {
				return msg, err
			}

			if err = verifySignature(config, MergeHeaders(msg.Headers, sheaders), digest, sig.Signature); err != nil {
				return msg, err
			}
		}

		return msg, nil
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
