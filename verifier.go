package bellmanverifier

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

type Vk struct {
	Alpha    *bn256.G1
	Beta     *bn256.G2
	Gamma    *bn256.G2
	Delta    *bn256.G2
	GammaABC []*bn256.G1
}

type VkRaw struct {
	Alpha    []string   `json:"alpha_g1"`
	Beta     [][]string `json:"beta_g2"`
	Gamma    [][]string `json:"gamma_g2"`
	Delta    [][]string `json:"delta_g2"`
	GammaABC [][]string `json:"ic"`
}

type Proof struct {
	A *bn256.G1
	B *bn256.G2
	C *bn256.G1
}

type ProofRaw struct {
	A      []string   `json:"a"`
	B      [][]string `json:"b"`
	C      []string   `json:"c"`
	Inputs []string   `json:"inputs"`
}

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

// ParsePublicRaw takes a json []byte and outputs the []*big.Int struct
func ParsePublicRaw(pj []byte) ([]*big.Int, error) {
	var pr []string
	err := json.Unmarshal(pj, &pr)
	if err != nil {
		return nil, err
	}
	var public []*big.Int
	for _, s := range pr {
		public = append(public, stringToBigInt(s))
	}
	return public, nil
}

// ParseVkRaw takes a json []byte and outputs the *Vk struct
func ParseVkRaw(vj []byte) (*Vk, error) {
	var vr VkRaw
	err := json.Unmarshal(vj, &vr)
	if err != nil {
		return nil, err
	}
	v, err := vkRawToVk(vr)
	return v, err
}

// ParseProofRaw takes a json []byte and outputs the *Proof struct
func ParseProofRaw(pj []byte) (*Proof, error) {
	var pr ProofRaw
	err := json.Unmarshal(pj, &pr)
	if err != nil {
		return nil, err
	}
	p, err := proofRawToProof(pr)
	return p, err
}

func vkRawToVk(vr VkRaw) (*Vk, error) {
	var v Vk
	var err error
	v.Alpha, err = hexToG1(vr.Alpha)
	if err != nil {
		return nil, err
	}

	v.Beta, err = hexToG2(vr.Beta)
	if err != nil {
		return nil, err
	}

	v.Gamma, err = hexToG2(vr.Gamma)
	if err != nil {
		return nil, err
	}

	v.Delta, err = hexToG2(vr.Delta)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(vr.GammaABC); i++ {
		p, err := hexToG1(vr.GammaABC[i])
		if err != nil {
			return nil, err
		}
		v.GammaABC = append(v.GammaABC, p)
	}

	return &v, nil
}

func proofRawToProof(pr ProofRaw) (*Proof, error) {
	var p Proof
	var err error
	p.A, err = hexToG1(pr.A)
	if err != nil {
		return nil, err
	}

	p.B, err = hexToG2(pr.B)
	if err != nil {
		return nil, err
	}

	p.C, err = hexToG1(pr.C)
	if err != nil {
		return nil, err
	}

	return &p, nil
}

var q = stringToBigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617")

// Verify performs the Groth16 zkSnark verification
func Verify(vk *Vk, proof *Proof, inputs []*big.Int) bool {
	if len(inputs)+1 != len(vk.GammaABC) {
		fmt.Println("len(inputs)+1 != len(vk.GammaABC)")
		return false
	}
	vkX := new(bn256.G1).ScalarBaseMult(stringToBigInt("0"))
	for i := 0; i < len(inputs); i++ {
		// check input inside field
		if inputs[0].Cmp(q) != -1 {
			return false
		}
		vkX = new(bn256.G1).Add(vkX, new(bn256.G1).ScalarMult(vk.GammaABC[i+1], inputs[i]))
	}
	vkX = new(bn256.G1).Add(vkX, vk.GammaABC[0])

	g1 := []*bn256.G1{proof.A, vk.Alpha.Neg(vk.Alpha), vkX.Neg(vkX), proof.C.Neg(proof.C)}
	g2 := []*bn256.G2{proof.B, vk.Beta, vk.Gamma, vk.Delta}
	return bn256.PairingCheck(g1, g2)
}
