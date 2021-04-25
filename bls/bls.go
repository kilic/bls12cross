package cross_bls

import (
	"bytes"
)

const (
	SignatureSize = 96
	PublicKeySize = 48
	SecretKeySize = 32
)

var dst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

type SecretKey interface {
	Sign(message []byte) Signature
	ToBytes() []byte
	Equal(other SecretKey) bool
	PublicKey() PublicKey
}

type PublicKey interface {
	FromBytes(compressed []byte) (PublicKey, error)
	ToBytes() []byte
	Equal(other PublicKey) bool
}

type Signature interface {
	FromBytes(compressed []byte) (Signature, error)
	ToBytes() []byte
	Equal(other Signature) bool
	Verify(publicKey PublicKey, message []byte) bool
	FastAggregateVerify(publicKeys []PublicKey, message []byte) bool
	AggregateVerify(publicKeys []PublicKey, messages [][]byte) bool
}

var zeroSecretKey = make([]byte, SecretKeySize)
var zeroPublicKey = make([]byte, PublicKeySize)
var infinitePublicKey []byte
var zeroSignature = make([]byte, SignatureSize)
var infiniteSignature []byte

func RandSecretKey() SecretKey {
	var secretKey SecretKey
	switch library {
	case libHerumi:
		secretKey = randHerumiSecretKey()
	case libBLST:
		secretKey = randBLSTSecretKey()
	case libKilic:
		secretKey = randKilicSecretKey()
	}
	return secretKey
}

func SecretKeyFromBytes(_secretKey []byte) (SecretKey, error) {
	if len(_secretKey) != SecretKeySize {
		return nil, errSecretKeySize
	}
	if bytes.Equal(zeroSecretKey, _secretKey) {
		return nil, errZeroSecretKey
	}
	var secretKey SecretKey
	var err error
	switch library {
	case libHerumi:
		secretKey, err = herumiSecretKeyFromBytes(_secretKey)
	case libBLST:
		secretKey, err = blstSecretKeyFromBytes(_secretKey)
	case libKilic:
		secretKey, err = kilicSecretKeyFromBytes(_secretKey)
	}

	if err != nil {
		return nil, err
	}
	return secretKey, nil
}

func PublicKeyFromBytes(compressed []byte) (PublicKey, error) {
	if len(compressed) != PublicKeySize {
		return nil, errPublicKeySize
	}
	if bytes.Equal(zeroPublicKey, compressed) {
		return nil, errZeroPublicKey
	}
	if bytes.Equal(infinitePublicKey, compressed) {
		return nil, errInfinitePublicKey
	}

	var publicKey PublicKey
	var err error
	switch library {
	case libHerumi:
		publicKey, err = new(HerumiPublicKey).FromBytes(compressed)
	case libBLST:
		publicKey, err = new(BLSTPublicKey).FromBytes(compressed)
	case libKilic:
		publicKey, err = new(KilicPublicKey).FromBytes(compressed)
	}
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func SignatureFromBytes(compressed []byte) (Signature, error) {
	if len(compressed) != SignatureSize {
		return nil, errSignatureSize
	}
	if bytes.Equal(zeroSignature, compressed) {
		return nil, errZeroSignature
	}
	if bytes.Equal(infiniteSignature, compressed) {
		return nil, errInfiniteSignature
	}
	var signature Signature
	var err error
	switch library {
	case libHerumi:
		signature, err = new(HerumiSignature).FromBytes(compressed)
	case libBLST:
		signature, err = new(BLSTSignature).FromBytes(compressed)
	case libKilic:
		signature, err = new(KilicSignature).FromBytes(compressed)
	}
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func AggreagatePublicKeys(publicKeys []PublicKey) PublicKey {
	var publicKey PublicKey
	switch library {
	case libHerumi:
		publicKey = herumiAggregatePublicKey(publicKeys)
	case libBLST:
		publicKey = blstAggregatePublicKey(publicKeys)
	case libKilic:
		publicKey = kilicAggregatePublicKey(publicKeys, nil)
	}
	return publicKey
}

func AggreagateSignatures(signatures []Signature) Signature {
	var signature Signature
	switch library {
	case libHerumi:
		signature = herumiAggregateSignature(signatures)
	case libBLST:
		signature = blstAggregateSignature(signatures)
	case libKilic:
		signature = kilicAggregateSignature(signatures, nil)
	}
	return signature
}
