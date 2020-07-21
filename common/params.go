package common

import "github.com/ldsec/lattigo/bfv"

var (
	// BFV parameters (128 bit security)
	params = bfv.DefaultParams[bfv.PN13QP218]
)

func init() {
	// Plaintext modulus
	params.T = 0x3ee0001
}

// GetParams get global params used for FHE bfv initialization
func GetParams() *bfv.Parameters {
	return params
}
