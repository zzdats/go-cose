package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"

	"github.com/zzdats/go-cose"
)

func main() {
	var err error

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Create new COSE_Sign1 message
	msg := cose.NewSign1Message()
	msg.SetContent([]byte("test"))
	// Add signer
	if msg.Signer, err = cose.NewSigner(cose.AlgorithmPS256, key); err != nil {
		panic(err)
	}
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
			verifier, err := msg.Signer.ToVerifier()
			if err != nil {
				return nil, err
			}
			return []*cose.Verifier{verifier}, nil
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
