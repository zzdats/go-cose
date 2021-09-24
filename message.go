// Copyright 2021 SIA ZZ Dats. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cose

// Message represents a COSE message.
type Message interface {
	// GetMessageTag returns the COSE message tag.
	GetMessageTag() uint64
	// GetContent returns the message content.
	GetContent() []byte
	// SetContent sets the message content.
	SetContent([]byte)
}
