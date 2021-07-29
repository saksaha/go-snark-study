package groth16

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/arnaucube/go-snark-study/circuitcompiler"
	"github.com/arnaucube/go-snark-study/r1csqap"
	"github.com/stretchr/testify/assert"

)

func TestGroth16MinimalFlow(t *testing.T) {
	fmt.Println("testing Groth16 minimal flow")
	// circuit function
	// y = x^3 + x + 5
	code := `
	func main(private s0, public s1):
		s2 = s0 * s0
		s3 = s2 * s0
		s4 = s3 + s0
		s5 = s4 + 5
		equals(s1, s5)
		out = 1 * 1
	`
	fmt.Print("\ncode of the circuit:\n")
	fmt.Printf("code: %s\n", code)

	// parse the code
	parser := circuitcompiler.NewParser(strings.NewReader(code))
	circuit, err := parser.Parse()
	assert.Nil(t, err)

	fmt.Printf("\ncircuit: %+v\n", circuit)

	b3 := big.NewInt(int64(3))
	privateInputs := []*big.Int{b3}
	b35 := big.NewInt(int64(35))
	publicSignals := []*big.Int{b35}

	fmt.Printf("\nb3 (private): %s, b35 (public): %s\n", b3, b35)

	// wittness
	w, err := circuit.CalculateWitness(privateInputs, publicSignals)
	assert.Nil(t, err)

	fmt.Printf("\nwitness, w: %s\n", w)

	// code to R1CS
	fmt.Println("\ngenerating R1CS from code")
	a, b, c := circuit.GenerateR1CS()
	fmt.Println("\nR1CS:")
	fmt.Println("a:", a)
	fmt.Println("b:", b)
	fmt.Println("c:", c)

	// R1CS to QAP
	// TODO zxQAP is not used and is an old impl, TODO remove
	alphas, betas, gammas, _ := Utils.PF.R1CSToQAP(a, b, c)

	fmt.Println("\nqap: ")
	fmt.Printf("\nalphas: %s\n", alphas)
	fmt.Printf("\nbetas: %s\n", betas)
	fmt.Printf("\ngammas: %s\n", gammas)

	assert.Equal(t, 8, len(alphas))
	assert.Equal(t, 8, len(alphas))
	assert.Equal(t, 8, len(alphas))
	assert.True(t, !bytes.Equal(alphas[1][1].Bytes(),
		big.NewInt(int64(0)).Bytes()))

	fmt.Printf("\nalphas[1][1].Bytes(): %d, int64(0).Bytes: %d\n",
		alphas[1][1].Bytes(), big.NewInt(int64(0)).Bytes())

	ax, bx, cx, px := Utils.PF.CombinePolynomials(w, alphas, betas, gammas)
	assert.Equal(t, 7, len(ax))
	assert.Equal(t, 7, len(bx))
	assert.Equal(t, 7, len(cx))
	assert.Equal(t, 13, len(px))

	fmt.Printf("\nax: %s\n", ax)
	fmt.Printf("\nbx: %s\n", bx)
	fmt.Printf("\ncx: %s\n", cx)
	fmt.Printf("\npx: %s\n", px)

	// ---
	// from here is the GROTH16
	// ---
	// calculate trusted setup
	fmt.Println("\ngroth")
	setup, err := GenerateTrustedSetup(len(w), *circuit, alphas, betas, gammas)
	assert.Nil(t, err)

	fmt.Printf("\nsetup.Toxic: %+v\n", setup.Toxic)
	fmt.Printf("\nsetup.Pk: %+v\n", setup.Pk)
	fmt.Printf("\nsetup.Vk: %+v\n", setup.Vk)
	// fmt.Println("\nt:", setup.Toxic.T)

	hx := Utils.PF.DivisorPolynomial(px, setup.Pk.Z)
	div, rem := Utils.PF.Div(px, setup.Pk.Z)

	fmt.Printf("\npx: %s\n", px)
	fmt.Printf("\nPk.Z: %s\n", setup.Pk.Z)
	fmt.Printf("\nhx: %s\n", hx)
	fmt.Printf("\ndiv: %s\n", div)
	fmt.Printf("\nrem: %s\n", rem)

	assert.Equal(t, hx, div)
	assert.Equal(t, rem, r1csqap.ArrayOfBigZeros(6))

	// hx==px/zx so px==hx*zx
	assert.Equal(t, px, Utils.PF.Mul(hx, setup.Pk.Z))

	// check length of polynomials H(x) and Z(x)
	assert.Equal(t, len(hx), len(px)-len(setup.Pk.Z)+1)

	proof, err := GenerateProofs(*circuit, setup.Pk, w, px)
	assert.Nil(t, err)

	fmt.Printf("\nproof.PiA: %s\n", proof.PiA)
	fmt.Printf("\nproofs.PiB: %s\n", proof.PiB)
	fmt.Printf("\nproofs.PiC: %s\n", proof.PiC)

	// fmt.Println("public signals:", proof.PublicSignals)
	fmt.Println("\nsignals:", circuit.Signals)
	fmt.Println("witness:", w)

	b35Verif := big.NewInt(int64(35))
	publicSignalsVerif := []*big.Int{b35Verif}
	before := time.Now()
	assert.True(t, VerifyProof(setup.Vk, proof, publicSignalsVerif, true))

	fmt.Println("verify proof time elapsed:", time.Since(before))

	// check that with another public input the verification returns false
	bOtherWrongPublic := big.NewInt(int64(34))
	wrongPublicSignalsVerif := []*big.Int{bOtherWrongPublic}
	assert.True(t, !VerifyProof(setup.Vk, proof, wrongPublicSignalsVerif, false))
}
