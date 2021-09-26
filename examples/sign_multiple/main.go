package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/zzdats/go-cose"
)

func main() {
	var err error

	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	key2, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		panic(err)
	}

	// Create new COSE_Sign message
	msg := cose.NewSignMessage()
	msg.SetContent([]byte("test"))

	// Add first signer
	signer1, err := cose.NewSigner(cose.AlgorithmPS256, key1)
	if err != nil {
		panic(err)
	}
	if err := signer1.Headers.Set(cose.HeaderKeyID, 1); err != nil {
		panic(err)
	}
	msg.AddSigner(signer1)

	// Add second signer
	signer2, err := cose.NewSigner(cose.AlgorithmPS512, key2)
	if err != nil {
		panic(err)
	}
	if err := signer2.Headers.Set(cose.HeaderKeyID, 2); err != nil {
		panic(err)
	}
	msg.AddSigner(signer2)

	// Encode to COSE byte array
	b, err := cose.StdEncoding.Encode(msg)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Signed message: %s\n", hex.EncodeToString(b))

	// Decode from COSE byte array
	dec, err := cose.StdEncoding.Decode(b, &cose.Config{
		// Provide signature verifier resolver
		GetVerifiers: func(headers *cose.Headers) ([]*cose.Verifier, error) {
			// You can use kid or some other info from headers to detect needed verification certificate
			// or just provide static verifier
			kid, err := headers.Get(cose.HeaderKeyID)
			if err != nil {
				return nil, err
			}
			if keyID, ok := kid.(int64); !ok {
				return nil, errors.New("invalid key id")
			} else if keyID == 1 {
				verifier, err := signer1.ToVerifier()
				if err != nil {
					return nil, err
				}
				return []*cose.Verifier{verifier}, nil
			} else if keyID == 2 {
				verifier, err := signer2.ToVerifier()
				if err != nil {
					return nil, err
				}
				return []*cose.Verifier{verifier}, nil
			} else {
				return nil, fmt.Errorf("unknown kid %d", keyID)
			}
		},
	})
	if err != nil && err != cose.ErrVerification {
		panic(err)
	}

	fmt.Printf("Decoded: %s\n", string(dec.GetContent()))
	if err == nil {
		fmt.Println("Signature verified")
	} else {
		fmt.Println("Signature is NOT valid")
	}
}
