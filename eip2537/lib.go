package cross_eip2537

import (
	"errors"
)

var (
	errEIP2537InvalidInputLength = errors.New("invalid input length")
	errEIP2537G1PointSubgroup    = errors.New("g1 point is not on correct subgroup")
	errEIP2537G2PointSubgroup    = errors.New("g2 point is not on correct subgroup")
)

const (
	libBLST  = "blst"
	libKilic = "kilic"
)

var library = libBLST

var dst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

func SetDST(_dst []byte) {
	dst = _dst
}

func init() {
	_init()
}

func _init() {
	switch library {
	case libBLST:
		initBLST()
	case libKilic:
		initKilic()
	}
}

func UseBLST() {
	library = libBLST
	initBLST()
}

func UseKilic() {
	library = libKilic
	initKilic()
}

var kilicInitialized = false
var blstInitialized = false

func initBLST() {
	if !blstInitialized {
		blstInitialized = true
	}
}

func initKilic() {
	if !kilicInitialized {
		kilicInitialized = true
	}
}
