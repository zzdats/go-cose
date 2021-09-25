package cose

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var dgcKnownIssues = []string{
	"ES/2DCode/raw/1501.json",     // invalid CBOR structure
	"ES/2DCode/raw/1502.json",     // invalid CBOR structure
	"ES/2DCode/raw/1503.json",     // invalid CBOR structure
	"ES/2DCode/raw/401.json",      // invalid elliptic curve
	"ES/2DCode/raw/402.json",      // invalid elliptic curve
	"ES/2DCode/raw/403.json",      // invalid elliptic curve
	"common/2DCode/raw/CBO2.json", // invalid CBOR structure
	"common/2DCode/raw/CO28.json", // invalid CBOR tag 61
	"common/2DCode/raw/CO22.json", // INVALID: KID in protected header not correct, KID in unprotected header correct
	"common/2DCode/raw/CO23.json", // INVALID: KID in protected header not present, KID in unprotected header not correct
}

func TestDgc(t *testing.T) {
	if os.Getenv("TEST_DGC") != "true" {
		t.Skip("Skipping DGC test suite")
	}
	err := filepath.Walk("test-data/dgc",
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if filepath.Ext(path) != ".json" {
				return nil
			}
			t.Run(path, func(t *testing.T) {
				for _, k := range dgcKnownIssues {
					if strings.HasSuffix(path, k) {
						t.Skip()
					}
				}
				testDgcTestCase(t, path)
			})
			return nil
		})
	require.NoError(t, err)
}

func parseKey(certData string) (crypto.PublicKey, error) {
	data, err := base64.StdEncoding.DecodeString(certData)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}

	return cert.PublicKey, nil
}

func testDgcTestCase(t *testing.T, path string) {
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var j map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &j))

	if j["COSE"] == nil || len(j["COSE"].(string)) == 0 || j["EXPECTEDRESULTS"].(map[string]interface{})["EXPECTEDVERIFY"] == nil {
		t.Skip()
	}

	b, err := hex.DecodeString(j["COSE"].(string))
	require.NoError(t, err)

	dec, err := StdEncoding.Decode(b, &Config{
		GetVerifiers: func(headers *Headers) ([]*Verifier, error) {
			kid, err := headers.Get(HeaderKeyID)
			if err != nil {
				return nil, err
			}
			if kid == nil || len(kid.([]byte)) == 0 {
				return nil, errors.New("kid missing")
			}
			algRaw, err := headers.GetProtected(HeaderAlgorithm)
			if err != nil {
				return nil, err
			}
			cert, err := parseKey(j["TESTCTX"].(map[string]interface{})["CERTIFICATE"].(string))
			if err != nil {
				return nil, err
			}
			if alg, ok := algRaw.(string); ok {
				verifier, err := NewVerifier(Algorithm(alg), cert)
				if err != nil {
					return nil, err
				}
				return []*Verifier{verifier}, nil
			}
			return nil, errors.New("alg not string")
		},
	})
	if !j["EXPECTEDRESULTS"].(map[string]interface{})["EXPECTEDVERIFY"].(bool) {
		require.ErrorIs(t, err, ErrVerification)
	} else {
		require.NoError(t, err)
	}

	require.NotEmpty(t, dec.GetContent())
}
