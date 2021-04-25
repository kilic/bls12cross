package cross_bls

import (
	"encoding/hex"
	"errors"
	"runtime"

	herumi "github.com/herumi/bls-eth-go-binary/bls"
	kilic "github.com/kilic/bls12-381"
	blst "github.com/supranational/blst/bindings/go"
)

var (
	errZeroSecretKey     = errors.New("zero secret key")
	errZeroPublicKey     = errors.New("zero public key")
	errInfinitePublicKey = errors.New("infinite public key")
	errInvalidPublicKey  = errors.New("invalid public key")
	errZeroSignature     = errors.New("zero signature")
	errInfiniteSignature = errors.New("infinite signature")
	errInvalidSignature  = errors.New("invalid signature")
	errSecretKeySize     = errors.New("invalid secret key size")
	errInvalidSecretKey  = errors.New("invalid secret key")
	errPublicKeySize     = errors.New("invalid public key size")
	errSignatureSize     = errors.New("invalid signature size")
)

const (
	libHerumi = "herumi"
	libBLST   = "blst"
	libKilic  = "kilic"
)

var library = libHerumi

func init() {
	_init()
}

func _init() {
	var err error
	infinitePublicKeyStr := "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	infinitePublicKey, err = hex.DecodeString(infinitePublicKeyStr)
	if err != nil {
		panic("cannot set infinite public key")
	}
	infiniteSignatureStr := "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	infiniteSignature, err = hex.DecodeString(infiniteSignatureStr)
	if err != nil {
		panic("cannot set infinite signature")
	}

	switch library {
	case libHerumi:
		initHerumi()
	case libBLST:
		initBLST()
	case libKilic:
		initKilic()
	}
}

func UseHerumi() {
	library = libHerumi
	initHerumi()
}

func UseBLST() {
	library = libBLST
	initBLST()
}

func UseKilic() {
	library = libKilic
	initKilic()
}

var blstSingleProc = false
var blstInitialized = false
var kilicInitialized = false
var herumiInitialized = false

func initBLST() {
	if !blstInitialized {
		if blstSingleProc {
			blst.SetMaxProcs(1)
		} else {
			maxProcs := runtime.GOMAXPROCS(0) - 1
			if maxProcs <= 0 {
				maxProcs = 1
			}
			blst.SetMaxProcs(maxProcs)
		}
		blstInitialized = true
	}
}

func initHerumi() {
	if !herumiInitialized {
		if err := herumi.Init(herumi.BLS12_381); err != nil {
			panic(err)
		}
		if err := herumi.SetETHmode(herumi.EthModeDraft07); err != nil {
			panic(err)
		}
		herumi.VerifyPublicKeyOrder(true)
		herumi.VerifySignatureOrder(true)
		herumiInitialized = true
	}
}

func initKilic() {
	if !kilicInitialized {
		kilicGroupOrder = new(kilic.Fr).FromBytes(kilic.NewG1().Q().Bytes())
		kilicInitialized = true
	}
}
