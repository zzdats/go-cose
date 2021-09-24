// Copyright 2021 SIA ZZ Dats. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cose

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeadersMergeHeadersProtectedTakesPriority(t *testing.T) {
	h1 := NewHeaders()
	h2 := NewHeaders()

	h1.protected[HeaderAlgorithm] = 1
	h2.unprotected[HeaderAlgorithm] = 2

	h := MergeHeaders(h1, h2)

	assert.Equal(t, 1, h.protected[HeaderAlgorithm])
	assert.Len(t, h.unprotected, 0)
}

func TestHeadersMergeHeaders(t *testing.T) {
	h1 := NewHeaders()
	h2 := NewHeaders()

	h1.protected[HeaderAlgorithm] = 1
	h2.protected[HeaderAlgorithm] = 2
	h2.unprotected[HeaderKeyID] = 2

	h := MergeHeaders(h1, h2)

	require.Len(t, h.protected, 1)
	assert.Equal(t, 2, h.protected[HeaderAlgorithm])
	require.Len(t, h.unprotected, 1)
	assert.Equal(t, 2, h.unprotected[HeaderKeyID])
}

func TestHeaders_GetSet(t *testing.T) {
	type args struct {
		key           interface{}
		expectedKey   interface{}
		value         interface{}
		expectedValue interface{}
	}
	tests := []struct {
		name      string
		args      args
		protected bool
		wantErr   bool
	}{
		{
			name: HeaderAlgorithm,
			args: args{
				key:           HeaderAlgorithm,
				expectedKey:   getCommonHeader(HeaderAlgorithm),
				value:         -7,
				expectedValue: string(AlgorithmES256),
			},
			protected: true,
		},
		{
			name: HeaderCritical,
			args: args{
				key:           HeaderCritical,
				expectedKey:   getCommonHeader(HeaderCritical),
				value:         []string{"reserved"},
				expectedValue: []string{"reserved"},
			},
			protected: true,
		},
		{
			name: HeaderContentType,
			args: args{
				key:           HeaderContentType,
				expectedKey:   getCommonHeader(HeaderContentType),
				value:         `application/cose; cose-type="cose-sign1"`,
				expectedValue: `application/cose; cose-type="cose-sign1"`,
			},
		},
		{
			name: HeaderKeyID,
			args: args{
				key:           HeaderKeyID,
				expectedKey:   getCommonHeader(HeaderKeyID),
				value:         1,
				expectedValue: 1,
			},
		},
		{
			name: HeaderIV,
			args: args{
				key:           HeaderIV,
				expectedKey:   getCommonHeader(HeaderIV),
				value:         123,
				expectedValue: 123,
			},
		},
		{
			name: HeaderPartialIV,
			args: args{
				key:           HeaderPartialIV,
				expectedKey:   getCommonHeader(HeaderPartialIV),
				value:         1,
				expectedValue: 1,
			},
		},
		{
			name: HeaderCounterSignature,
			args: args{
				key:           HeaderCounterSignature,
				expectedKey:   getCommonHeader(HeaderCounterSignature),
				value:         1,
				expectedValue: 1,
			},
		},
		{
			name: "string key",
			args: args{
				key:           "reserved",
				expectedKey:   "reserved",
				value:         true,
				expectedValue: true,
			},
		},
		{
			name: "int key",
			args: args{
				key:           123,
				expectedKey:   int64(123),
				value:         "test",
				expectedValue: "test",
			},
		},
		{
			name: "invalid key type",
			args: args{
				key:   uint(1),
				value: "test",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHeaders()
			err := h.Set(tt.args.key, tt.args.value)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				if tt.protected {
					require.Len(t, h.protected, 1)
					assert.Equal(t, tt.args.value, h.protected[tt.args.expectedKey])
				} else {
					require.Len(t, h.unprotected, 1)
					assert.Equal(t, tt.args.value, h.unprotected[tt.args.expectedKey])
				}

				val, err := h.Get(tt.args.key)
				require.NoError(t, err)
				assert.Equal(t, tt.args.expectedValue, val)
			}
		})
	}
}

func TestHeaders_GetSetProtected(t *testing.T) {
	type args struct {
		key           interface{}
		expectedKey   interface{}
		value         interface{}
		expectedValue interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: HeaderAlgorithm,
			args: args{
				key:           HeaderAlgorithm,
				expectedKey:   getCommonHeader(HeaderAlgorithm),
				value:         -7,
				expectedValue: string(AlgorithmES256),
			},
		},
		{
			name: HeaderCritical,
			args: args{
				key:           HeaderCritical,
				expectedKey:   getCommonHeader(HeaderCritical),
				value:         []string{"reserved"},
				expectedValue: []string{"reserved"},
			},
		},
		{
			name: "string key",
			args: args{
				key:           "reserved",
				expectedKey:   "reserved",
				value:         true,
				expectedValue: true,
			},
		},
		{
			name: "int key",
			args: args{
				key:           123,
				expectedKey:   int64(123),
				value:         "test",
				expectedValue: "test",
			},
		},
		{
			name: "invalid key type",
			args: args{
				key:   uint(1),
				value: "test",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHeaders()
			err := h.SetProtected(tt.args.key, tt.args.value)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.Len(t, h.protected, 1)
				assert.Equal(t, tt.args.value, h.protected[tt.args.expectedKey])

				val, err := h.GetProtected(tt.args.key)
				require.NoError(t, err)
				assert.Equal(t, tt.args.expectedValue, val)
			}
		})
	}
}

func TestHeaders_DeleteCommon(t *testing.T) {
	h := NewHeaders()
	h.protected[getCommonHeader(HeaderAlgorithm)] = 1
	h.unprotected[getCommonHeader(HeaderAlgorithm)] = 2

	h.Delete(HeaderAlgorithm)

	assert.Len(t, h.protected, 0)
	assert.Len(t, h.unprotected, 0)
}

func TestHeaders_Delete(t *testing.T) {
	h := NewHeaders()
	h.protected[int64(5)] = 1

	h.Delete(5)

	assert.Len(t, h.protected, 0)
}
