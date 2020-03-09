package bellmanverifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePoints(t *testing.T) {
	aHex := []string{"0x2cdfab288afda1ba399d60951423e76445754b7d2e7827634732988373c8e0ff", "0x1bb2e3543dfdd373610db3ea82703bc70e4d6f01b5c0e10709e27545670824f4"}
	a, err := hexToG1(aHex)
	assert.Nil(t, err)
	assert.Equal(t, "bn256.G1(2cdfab288afda1ba399d60951423e76445754b7d2e7827634732988373c8e0ff, 1bb2e3543dfdd373610db3ea82703bc70e4d6f01b5c0e10709e27545670824f4)", a.String())

	bHex := [][]string{
		[]string{
			"0x0f9cd75cae408d3b6d2731035dbb6aa6f66cf900c1d64b46510cbbcd7cf94f64",
			"0x165997362d7c2bf5672d16206fbee620ad8eb54f609b98c49c7c6287c9979077",
		},
		[]string{
			"0x0392982b7cd7bdbbee79d5f808c67ead8ef3e2347810b546b419da5f738aab92",
			"0x0f94d6781b9de113b86abd1930accd2260d0c979d520bc1a0e79dec3c8ce76a3",
		},
	}
	b, err := hexToG2(bHex)
	assert.Nil(t, err)
	assert.Equal(t, "bn256.G2((165997362d7c2bf5672d16206fbee620ad8eb54f609b98c49c7c6287c9979077, 0f9cd75cae408d3b6d2731035dbb6aa6f66cf900c1d64b46510cbbcd7cf94f64), (0f94d6781b9de113b86abd1930accd2260d0c979d520bc1a0e79dec3c8ce76a3, 0392982b7cd7bdbbee79d5f808c67ead8ef3e2347810b546b419da5f738aab92))", b.String())

	gHex := [][]string{
		[]string{
			"0x2d0c4fa1239184802aeda1f206e49104940aa3eccc1b3e0141c25b2dba8e7caf",
			"0x15c9b1123841897787badbe858eb00943fc8a99454666f21acf4e79e13547471",
		},
		[]string{
			"0x256ad09ecb0abc15fd48f20c37d28ffcf0f8eb3b23cb10cdeee7365b598963ac",
			"0x2bc9bc381cf68badd992338c637b36b54936b69cb8560eaf5a8cbe2c20ff8522",
		},
	}
	g, err := hexToG2(gHex)
	assert.Nil(t, err)
	assert.Equal(t, "bn256.G2((15c9b1123841897787badbe858eb00943fc8a99454666f21acf4e79e13547471, 2d0c4fa1239184802aeda1f206e49104940aa3eccc1b3e0141c25b2dba8e7caf), (2bc9bc381cf68badd992338c637b36b54936b69cb8560eaf5a8cbe2c20ff8522, 256ad09ecb0abc15fd48f20c37d28ffcf0f8eb3b23cb10cdeee7365b598963ac))", g.String())
}
