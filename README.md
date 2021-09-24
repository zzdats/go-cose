# go-cose

[![PkgGoDev](https://pkg.go.dev/badge/github.com/zzdats/go-cose)](https://pkg.go.dev/github.com/zzdats/go-cose)
[![Build Status](https://cloud.drone.io/api/badges/zzdats/go-cose/status.svg?ref=refs/heads/main)](https://cloud.drone.io/zzdats/go-cose)
[![codecov](https://codecov.io/gh/zzdats/go-cose/branch/main/graph/badge.svg?token=BF9M52EG0G)](https://codecov.io/gh/zzdats/go-cose)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A [COSE](https://tools.ietf.org/html/rfc8152) library for Go.

## Supported COSE messages

* COSE Single Signer Data Object `cose-sign1`

### Supported COSE algorithms

* Signing and verification:
  * `PS256` - RSASSA-PSS w/ SHA-256
  * `PS384` - RSASSA-PSS w/ SHA-384
  * `PS384` - RSASSA-PSS w/ SHA-512
  * `ES256` - ECDSA w/ SHA-256
  * `ES384` - ECDSA w/ SHA-384
  * `ES512` - ECDSA w/ SHA-512
  * `EdDSA` - Ed25519

> Thanks to Mozilla for creating [mozilla-services/go-cose](https://github.com/mozilla-services/go-cose) library for some inspiration.
