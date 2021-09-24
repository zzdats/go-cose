package main

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/zzdats/go-cose"
)

const pubCertData = `MIICEjCCAbmgAwIBAgIUTExVw4anJr4PZhNn3w8UgGwoQGUwCgYIKoZIzj0EAwIwZjELMAkGA1UEBhMCTFYxLTArBgNVBAoMJE5hY2lvbsOEwoFsYWlzIFZlc2Vsw4TCq2JhcyBkaWVuZXN0czENMAsGA1UECwwEQ1NDQTEZMBcGA1UEAwwQQ1NDQSBER0MgTFYgVGVzdDAeFw0yMTA1MTMwNzM2MTZaFw0yNTA1MTIwNzM2MTZaMGYxCzAJBgNVBAYTAkxWMS0wKwYDVQQKDCROYWNpb27DhMKBbGFpcyBWZXNlbMOEwqtiYXMgZGllbmVzdHMxDTALBgNVBAsMBENTQ0ExGTAXBgNVBAMMEENTQ0EgREdDIExWIFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAREAeqbcI/ljWtS/UAvYhF4ubd1RQpOd/NrgLunZb3HAbBW/8h1dxPr1DSWQmxxXlGR/TitYtL1ZuxeRWfl8bGDo0UwQzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUTP6CwP1AoJEnvrISXSiv4q+Q0U0wCgYIKoZIzj0EAwIDRwAwRAIgU3W1knii0mIcfFBTzE3c0GjL8zTg8oSaUJwrSKq0eVwCIFfT95WJ2qIQA9a7abobrHLmnYCP+K/lbtwQ2tNErpc3`
const coseData = `d28443a10126a104484dfc0b3070d7230b59015ca401624c56041a62a9939b061a60c8601b390103a101a46376657265312e302e30636e616da462666e67c4b6656c70697363666e74664b454c50495362676e6a4dc481727469c586c5a163676e74674d415254494e5363646f626a313939332d30392d3133617481aa62746769383430353339303036627474684c50363436342d34626e6d7832412a5354415220466f72746974756465204b697420322e30202853696e6761706f72652048534129203f20504352206b697462736374323032312d30362d31325430393a30303a30305a62647274323032312d30362d31325430393a30303a30305a62747269323630343135303030627463634e564462636f624c5662697378204e6163696f6ec4816c61697320766573656cc4ab626173206469656e65737473626369782f75726e3a757663693a30313a6c763a3363653362623365383033346364376561653236646639656435636130383962584049232f3562692ca90585994d02e0131058e9800797449e5fbc4ba323a339adc4895872959e813ae34e4dcb9e0157113f97c6307db2bbe54b66767482fe571363`

// func cbor2json(data []byte) ([]byte, error) {
// 	var st map[interface{}]interface{}
// 	if err := cbor.Unmarshal(data, &st); err != nil {
// 		return nil, err
// 	}
// 	return json.Marshal(st)
// }

func parseKey() (crypto.PublicKey, error) {
	data, err := base64.RawStdEncoding.DecodeString(pubCertData)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}

	return cert.PublicKey, nil
}

func main() {
	pub, err := parseKey()
	if err != nil {
		panic(err)
	}

	coseHex := coseData

	if len(os.Args) > 1 {
		coseHex = os.Args[1]
	}

	b, err := hex.DecodeString(coseHex)
	if err != nil {
		panic(err)
	}

	// Decode from COSE byte array
	dec, err := cose.StdEncoding.Decode(b, &cose.Config{
		GetVerifiers: func(headers *cose.Headers) ([]*cose.Verifier, error) {
			var kid []byte
			hkid, err := headers.Get(cose.HeaderKeyID)
			if err != nil {
				return nil, err
			}
			if rk, ok := hkid.([]byte); ok && rk != nil {
				kid = rk
			}
			if len(kid) > 0 {
				kidVal := "0x" + hex.EncodeToString(kid)
				fmt.Printf("Signer KID: %s\n", kidVal)

				if kidVal == "0x4dfc0b3070d7230b" {
					algRaw, err := headers.GetProtected(cose.HeaderAlgorithm)
					if err != nil {
						return nil, err
					}
					if alg, ok := algRaw.(string); ok {
						verifier, err := cose.NewVerifier(cose.Algorithm(alg), pub)
						if err != nil {
							return nil, err
						}
						return []*cose.Verifier{verifier}, nil
					}
				}
			}
			return nil, errors.New("key not found")
		},
	})
	if dec != nil {
		// data, err := cbor2json(dec.GetContent())
		// if err != nil {
		// 	panic(err)
		// }
		fmt.Printf("Decoded: %s\n", string(dec.GetContent()))
	}
	if err == nil {
		fmt.Println("Signature verified")
	} else {
		fmt.Printf("Signature is NOT valid: %s\n", err.Error())
	}
}
