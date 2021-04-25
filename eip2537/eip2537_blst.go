package cross_eip2537

import (
	blst "github.com/sean-sn/blst_eip2537/go"
)

func BLSTG1Add(input []byte) ([]byte, error) {
	return blst.G1Add(input)
}

func BLSTG1Mul(input []byte) ([]byte, error) {
	return blst.G1Mul(input)
}

func BLSTG1MultiExp(input []byte) ([]byte, error) {
	return blst.G1Multiexp(input)
}

func BLSTG2Add(input []byte) ([]byte, error) {
	return blst.G2Add(input)
}

func BLSTG2Mul(input []byte) ([]byte, error) {
	return blst.G2Mul(input)
}

func BLSTG2MultiExp(input []byte) ([]byte, error) {
	return blst.G2Multiexp(input)
}

func BLSTPairing(input []byte) ([]byte, error) {
	return blst.Pairing(input)
}

func BLSTMapG1(input []byte) ([]byte, error) {
	return blst.MapFpToG1(input)
}

func BLSTMapG2(input []byte) ([]byte, error) {
	return blst.MapFp2ToG2(input)
}
