package bellmanverifier

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestParseProof(t *testing.T) {
	proofJson, err := ioutil.ReadFile("testdata/proof0.json")
	require.Nil(t, err)
	vkJson, err := ioutil.ReadFile("testdata/vk0.json")
	require.Nil(t, err)

	proof, err := ParseProofRaw(proofJson)
	require.Nil(t, err)
	vk, err := ParseVkRaw(vkJson)
	require.Nil(t, err)

	assert.Equal(t, "bn256.G1(2cdfab288afda1ba399d60951423e76445754b7d2e7827634732988373c8e0ff, 1bb2e3543dfdd373610db3ea82703bc70e4d6f01b5c0e10709e27545670824f4)", proof.A.String())
	assert.Equal(t, "bn256.G1(0b710c2f32925ad4576f925e8c5954c7dace91437fd6bc3ded1d15b70990a885, 2cd6ea79e38ad566aceb09113e67142d278d12a76b49031ce1bde1dedca696b4)", proof.C.String())
	assert.Equal(t, "bn256.G1(0c0e14d07f2281c592952c72f86a7f5df7189ab6d00b84609ad777fbf062f38d, 2f60c0e4913ec4691bdf2dd9f2b5fed9b80a3267eec107b9f1d69418a19a30a8)", vk.Alpha.String())
	assert.Equal(t, "bn256.G2((2275d97dce5445433ec7bc6d01c35f0afad9afcf6f3350cd15eeef1023242c01, 0b5f21c2d981916cd5e1037b446b170b6c60dd184fdbb3381b7d0880fb48300d), (2c2a08a60032f536afbcb21c079b563cdce68b7ef906e973c52f574121a95df0, 1690100372c53776b60c0ee56926debb4d0acee90f7952ecc63861e0269a098a))", vk.Beta.String())
	assert.Equal(t, "bn256.G2((15c9b1123841897787badbe858eb00943fc8a99454666f21acf4e79e13547471, 2d0c4fa1239184802aeda1f206e49104940aa3eccc1b3e0141c25b2dba8e7caf), (2bc9bc381cf68badd992338c637b36b54936b69cb8560eaf5a8cbe2c20ff8522, 256ad09ecb0abc15fd48f20c37d28ffcf0f8eb3b23cb10cdeee7365b598963ac))", vk.Gamma.String())
}

func TestVerify0(t *testing.T) {
	proofJson, err := ioutil.ReadFile("testdata/proof0.json")
	require.Nil(t, err)
	vkJson, err := ioutil.ReadFile("testdata/vk0.json")
	require.Nil(t, err)
	publicJson, err := ioutil.ReadFile("testdata/public0.json")
	require.Nil(t, err)

	public, err := ParsePublicRaw(publicJson)
	require.Nil(t, err)
	proof, err := ParseProofRaw(proofJson)
	require.Nil(t, err)
	vk, err := ParseVkRaw(vkJson)
	require.Nil(t, err)

	v := Verify(vk, proof, public)
	assert.True(t, v)
}

func TestVerify1(t *testing.T) {
	proofJson, err := ioutil.ReadFile("testdata/proof1.json")
	require.Nil(t, err)
	vkJson, err := ioutil.ReadFile("testdata/vk1.json")
	require.Nil(t, err)
	publicJson, err := ioutil.ReadFile("testdata/public1.json")
	require.Nil(t, err)

	public, err := ParsePublicRaw(publicJson)
	require.Nil(t, err)
	proof, err := ParseProofRaw(proofJson)
	require.Nil(t, err)
	vk, err := ParseVkRaw(vkJson)
	require.Nil(t, err)

	v := Verify(vk, proof, public)
	assert.True(t, v)
}

func BenchmarkVerify(b *testing.B) {
	proofJson, err := ioutil.ReadFile("testdata/proof0.json")
	require.Nil(b, err)
	vkJson, err := ioutil.ReadFile("testdata/vk0.json")
	require.Nil(b, err)
	publicJson, err := ioutil.ReadFile("testdata/public0.json")
	require.Nil(b, err)

	public, err := ParsePublicRaw(publicJson)
	require.Nil(b, err)
	proof, err := ParseProofRaw(proofJson)
	require.Nil(b, err)
	vk, err := ParseVkRaw(vkJson)
	require.Nil(b, err)

	for i := 0; i < b.N; i++ {
		Verify(vk, proof, public)
	}
}
