# go-bellman-verifier [![Go Report Card](https://goreportcard.com/badge/github.com/arnaucube/go-bellman-verifier)](https://goreportcard.com/report/github.com/arnaucube/go-bellman-verifier)  [![Build Status](https://travis-ci.org/arnaucube/go-bellman-verifier.svg?branch=master)](https://travis-ci.org/arnaucube/go-bellman-verifier)

Groth16 zkSNARK bellman proof verifier

Verify [Groth16](https://eprint.iacr.org/2016/260.pdf) proofs generated from [bellman](https://github.com/zkcrypto/bellman), using [cloudflare/bn256](https://github.com/ethereum/go-ethereum/tree/master/crypto/bn256/cloudflare) (used by [go-ethereum](https://github.com/ethereum/go-ethereum)) for the Pairing.


## Usage
```go
public, err := ParsePublicRaw(publicJson)
require.Nil(t, err)
proof, err := ParseProofRaw(proofJson)
require.Nil(t, err)
vk, err := ParseVkRaw(vkJson)
require.Nil(t, err)

v := Verify(vk, proof, public)
assert.True(t, v)
```

