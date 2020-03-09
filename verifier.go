package bellmanverifier

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

func hexToG1(h []string) (*bn256.G1, error) {
	in := ""
	for i := range h {
		in += strings.TrimPrefix(h[i], "0x")
	}

	b, err := hex.DecodeString(in)
	if err != nil {
		return nil, err
	}
	p := new(bn256.G1)
	_, err = p.Unmarshal(b)

	return p, err
}

func hexToG2Regular(h [][]string) (*bn256.G2, error) {
	in := ""
	for i := 0; i < len(h); i++ {
		for j := 0; j < len(h[i]); j++ {
			in += strings.TrimPrefix(h[i][j], "0x")
		}
	}

	b, err := hex.DecodeString(in)
	if err != nil {
		return nil, err
	}
	p := new(bn256.G2)
	_, err = p.Unmarshal(b)
	return p, err
}

func hexToG2(h [][]string) (*bn256.G2, error) {
	in := ""
	in += strings.TrimPrefix(h[0][1], "0x") // note that values are switched
	in += strings.TrimPrefix(h[0][0], "0x")
	in += strings.TrimPrefix(h[1][1], "0x")
	in += strings.TrimPrefix(h[1][0], "0x")

	b, err := hex.DecodeString(in)
	if err != nil {
		return nil, err
	}
	p := new(bn256.G2)
	_, err = p.Unmarshal(b)
	return p, err
}

func stringToBigInt(s string) *big.Int {
	base := 10
	if bytes.HasPrefix([]byte(s), []byte("0x")) {
		base = 16
		s = strings.TrimPrefix(s, "0x")
	}
	n, ok := new(big.Int).SetString(s, base)
	if !ok {
		panic(fmt.Errorf("Can not parse string to *big.Int: %s", s))
	}
	return n
}
