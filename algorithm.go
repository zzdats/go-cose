package cose

import (
	"crypto"
	"crypto/elliptic"
)

// Algorithm name
type Algorithm string

const (
	// AlgorithmPS256 for signing with RSASSA-PSS w/ SHA-256
	AlgorithmPS256 Algorithm = "PS256"
	// AlgorithmPS384 for signing with RSASSA-PSS w/ SHA-384
	AlgorithmPS384 Algorithm = "PS384"
	// AlgorithmPS512 for signing with RSASSA-PSS w/ SHA-512
	AlgorithmPS512 Algorithm = "PS512"
	// AlgorithmES512 for signing with ECDSA w/ SHA-512
	AlgorithmES512 Algorithm = "ES512"
	// AlgorithmES384 for signing with ECDSA w/ SHA-384
	AlgorithmES384 Algorithm = "ES384"
	// AlgorithmES256 for signing with ECDSA w/ SHA-256
	AlgorithmES256 Algorithm = "ES256"
	// AlgorithmEdDSA for signing with EdDSA/Ed25519
	AlgorithmEdDSA Algorithm = "EdDSA"
)

func getAlg(name string) *algorithm {
	for _, a := range algorithms {
		if a.Name == name {
			return a
		}
	}
	return nil
}

func getAlgByValue(value int64) *algorithm {
	for _, a := range algorithms {
		if a.Value == value {
			return a
		}
	}
	return nil
}

type algorithmType int

const (
	algorithmTypeUnsupported algorithmType = iota
	algorithmTypeKeyRSA
	algorithmTypeKeyECDSA
	algorithmTypeKeyED25519
)

type algorithm struct {
	Name  string
	Value int64

	Hash crypto.Hash   // hash function
	Type algorithmType // required key type

	MinKeySize       int            // minimimum key size
	KeyEllipticCurve elliptic.Curve // key elliptic curve type
}

// COSE algorithms from
var algorithms = []*algorithm{
	// RSASSA-PKCS1-v1_5 using SHA-1
	{
		Name:  "RS1",
		Value: -65535,
	},
	// WalnutDSA signature
	{
		Name:  "WalnutDSA",
		Value: -260,
	},
	// RSASSA-PKCS1-v1_5 using SHA-512
	{
		Name:  "RS512",
		Value: -259,
	},
	// RSASSA-PKCS1-v1_5 using SHA-384
	{
		Name:  "RS384",
		Value: -258,
	},
	// RSASSA-PKCS1-v1_5 using SHA-256
	{
		Name:  "RS256",
		Value: -257,
	},
	// ECDSA using secp256k1 curve and SHA-256
	{
		Name:  "ES256K",
		Value: -47,
	},
	// HSS/LMS hash-based digital signature
	{
		Name:  "HSS-LMS",
		Value: -46,
	},
	// SHAKE-256 512-bit Hash Value
	{
		Name:  "SHAKE256",
		Value: -45,
	},
	// SHA-2 512-bit Hash
	{
		Name:  "SHA-512",
		Value: -44,
	},
	// SHA-2 384-bit Hash
	{
		Name:  "SHA-384",
		Value: -43,
	},
	// RSAES-OAEP w/ SHA-512
	{
		Name:  "RSAES-OAEP w/ SHA-512",
		Value: -42,
	},
	// RSAES-OAEP w/ SHA-256
	{
		Name:  "RSAES-OAEP w/ SHA-256",
		Value: -41,
	},
	// RSAES-OAEP w/ SHA-1
	{
		Name:  "RSAES-OAEP w/ RFC 8017 default parameters",
		Value: -40,
	},
	// RSASSA-PSS w/ SHA-512
	{
		Name:       string(AlgorithmPS512),
		Value:      -39,
		Type:       algorithmTypeKeyRSA,
		Hash:       crypto.SHA512,
		MinKeySize: 2048,
	},
	// RSASSA-PSS w/ SHA-384
	{
		Name:       string(AlgorithmPS384),
		Value:      -38,
		Type:       algorithmTypeKeyRSA,
		Hash:       crypto.SHA384,
		MinKeySize: 2048,
	},
	// RSASSA-PSS w/ SHA-256
	{
		Name:       string(AlgorithmPS256),
		Value:      -37,
		Type:       algorithmTypeKeyRSA,
		Hash:       crypto.SHA256,
		MinKeySize: 2048,
	},
	// ECDSA w/ SHA-512
	{
		Name:             string(AlgorithmES512),
		Value:            -36,
		Type:             algorithmTypeKeyECDSA,
		Hash:             crypto.SHA512,
		KeyEllipticCurve: elliptic.P521(),
	},
	// ECDSA w/ SHA-384
	{
		Name:             string(AlgorithmES384),
		Value:            -35,
		Type:             algorithmTypeKeyECDSA,
		Hash:             crypto.SHA384,
		KeyEllipticCurve: elliptic.P384(),
	},
	// ECDH SS w/ Concat KDF and AES Key Wrap w/ 256-bit key
	{
		Name:  "ECDH-SS + A256KW",
		Value: -34,
	},
	// ECDH SS w/ Concat KDF and AES Key Wrap w/ 192-bit key
	{
		Name:  "ECDH-SS + A192KW",
		Value: -33,
	},
	// ECDH SS w/ Concat KDF and AES Key Wrap w/ 128-bit key
	{
		Name:  "ECDH-SS + A128KW",
		Value: -32,
	},
	// ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key
	{
		Name:  "ECDH-ES + A256KW",
		Value: -31,
	},
	// ECDH ES w/ Concat KDF and AES Key Wrap w/ 192-bit key
	{
		Name:  "ECDH-ES + A192KW",
		Value: -30,
	},
	// ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key
	{
		Name:  "ECDH-ES + A128KW",
		Value: -29,
	},
	// ECDH SS w/ HKDF - generate key directly
	{
		Name:  "ECDH-SS + HKDF-512",
		Value: -28,
	},
	// ECDH SS w/ HKDF - generate key directly
	{
		Name:  "ECDH-SS + HKDF-256",
		Value: -27,
	},
	// ECDH ES w/ HKDF - generate key directly
	{
		Name:  "ECDH-ES + HKDF-512",
		Value: -26,
	},
	// ECDH ES w/ HKDF - generate key directly
	{
		Name:  "ECDH-ES + HKDF-256",
		Value: -25,
	},
	// SHAKE-128 256-bit Hash Value
	{
		Name:  "SHAKE128",
		Value: -18,
	},
	// SHA-2 512-bit Hash truncated to 256-bits
	{
		Name:  "SHA-512/256",
		Value: -17,
	},
	// SHA-2 256-bit Hash
	{
		Name:  "SHA-256",
		Value: -16,
	},
	// SHA-2 256-bit Hash truncated to 64-bits
	{
		Name:  "SHA-256/64",
		Value: -15,
	},
	// SHA-1 Hash
	{
		Name:  "SHA-1",
		Value: -14,
	},
	// Shared secret w/ AES-MAC 256-bit key
	{
		Name:  "direct+HKDF-AES-256",
		Value: -13,
	},
	// Shared secret w/ AES-MAC 128-bit key
	{
		Name:  "direct+HKDF-AES-128",
		Value: -12,
	},
	// Shared secret w/ HKDF and SHA-512
	{
		Name:  "direct+HKDF-SHA-512",
		Value: -11,
	},
	// Shared secret w/ HKDF and SHA-256
	{
		Name:  "direct+HKDF-SHA-256",
		Value: -10,
	},
	// EdDSA
	{
		Name:  string(AlgorithmEdDSA),
		Value: -8,
		Type:  algorithmTypeKeyED25519,
	},
	// ECDSA w/ SHA-256
	{
		Name:             string(AlgorithmES256),
		Value:            -7,
		Type:             algorithmTypeKeyECDSA,
		Hash:             crypto.SHA256,
		KeyEllipticCurve: elliptic.P256(),
	},
	// Direct use of CEK
	{
		Name:  "direct",
		Value: -6,
	},
	// AES Key Wrap w/ 256-bit key
	{
		Name:  "A256KW",
		Value: -5,
	},
	// AES Key Wrap w/ 192-bit key
	{
		Name:  "A192KW",
		Value: -4,
	},
	// AES Key Wrap w/ 128-bit key
	{
		Name:  "A128KW",
		Value: -3,
	},
	// AES-GCM mode w/ 128-bit key, 128-bit tag
	{
		Name:  "A128GCM",
		Value: 1,
	},
	// AES-GCM mode w/ 192-bit key, 128-bit tag
	{
		Name:  "A192GCM",
		Value: 2,
	},
	// AES-GCM mode w/ 256-bit key, 128-bit tag
	{
		Name:  "A256GCM",
		Value: 3,
	},
	// HMAC w/ SHA-256 truncated to 64 bits
	{
		Name:  "HMAC 256/64",
		Value: 4,
	},
	// HMAC w/ SHA-256
	{
		Name:  "HMAC 256/256",
		Value: 5,
	},
	// HMAC w/ SHA-384
	{
		Name:  "HMAC 384/384",
		Value: 6,
	},
	// HMAC w/ SHA-512
	{
		Name:  "HMAC 512/512",
		Value: 7,
	},
	// AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce
	{
		Name:  "AES-CCM-16-64-128",
		Value: 10,
	},
	// AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce
	{
		Name:  "AES-CCM-16-64-256",
		Value: 11,
	},
	// AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce
	{
		Name:  "AES-CCM-64-64-128",
		Value: 12,
	},
	// AES-CCM mode 256-bit key, 64-bit tag, 7-byte nonce
	{
		Name:  "AES-CCM-64-64-256",
		Value: 13,
	},
	// AES-MAC 128-bit key, 64-bit tag
	{
		Name:  "AES-MAC 128/64",
		Value: 14,
	},
	// AES-MAC 256-bit key, 64-bit tag
	{
		Name:  "AES-MAC 256/64",
		Value: 15,
	},
	// ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag
	{
		Name:  "ChaCha20/Poly1305",
		Value: 24,
	},
	// AES-MAC 128-bit key, 128-bit tag
	{
		Name:  "AES-MAC 128/128",
		Value: 25,
	},
	// AES-MAC 256-bit key, 128-bit tag
	{
		Name:  "AES-MAC 256/128",
		Value: 26,
	},
	// AES-CCM mode 128-bit key, 128-bit tag, 13-byte nonce
	{
		Name:  "AES-CCM-16-128-128",
		Value: 30,
	},
	// AES-CCM mode 256-bit key, 128-bit tag, 13-byte nonce
	{
		Name:  "AES-CCM-16-128-256",
		Value: 31,
	},
	// AES-CCM mode 128-bit key, 128-bit tag, 7-byte nonce
	{
		Name:  "AES-CCM-64-128-128",
		Value: 32,
	},
	// AES-CCM mode 256-bit key, 128-bit tag, 7-byte nonce
	{
		Name:  "AES-CCM-64-128-256",
		Value: 33,
	},
	// For doing IV generation for symmetric algorithms.
	{
		Name:  "IV-GENERATION",
		Value: 34,
	},
}
