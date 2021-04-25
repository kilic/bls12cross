package cross_bls

import (
	"crypto/rand"
	"errors"

	blst "github.com/supranational/blst/bindings/go"
)

type blstPublicKey = blst.P1Affine
type blstSecretKey = blst.SecretKey
type blstSignature = blst.P2Affine

type BLSTPublicKey struct {
	p *blst.P1Affine
}

type BLSTSecretKey struct {
	s *blst.SecretKey
}

type BLSTSignature struct {
	p *blst.P2Affine
}

var blstOptionCheckSignatureSubgroupInVerification = false
var blstOptionValidatePublicKeyInVerification = false

func randBLSTSecretKey() SecretKey {
	var t [32]byte
	_, _ = rand.Read(t[:])
	secretKey := blst.KeyGen(t[:])
	return &BLSTSecretKey{secretKey}
}

func blstSecretKeyFromBytes(in []byte) (SecretKey, error) {
	if len(in) != SecretKeySize {
		return nil, errSecretKeySize
	}
	secretKey := new(blstSecretKey)
	secretKey = secretKey.Deserialize(in)
	if secretKey == nil {
		return nil, errInvalidSecretKey
	}
	return &BLSTSecretKey{secretKey}, nil
}

func (secretKey *BLSTSecretKey) Equal(other SecretKey) bool {
	return secretKey.s.Equals(other.(*BLSTSecretKey).s)
}

func (secretKey *BLSTSecretKey) PublicKey() PublicKey {
	return &BLSTPublicKey{new(blstPublicKey).From(secretKey.s)}
}

func (secretKey *BLSTSecretKey) Sign(message []byte) Signature {
	blstSignature := new(blstSignature).Sign(secretKey.s, message, dst)
	return &BLSTSignature{blstSignature}
}

func (secretKey *BLSTSecretKey) ToBytes() []byte {
	return secretKey.s.Serialize()
}

func (publicKey *BLSTPublicKey) FromBytes(compressed []byte) (PublicKey, error) {

	if len(compressed) != PublicKeySize {
		return nil, errors.New("invalid public key size")
	}
	blstPublicKey := new(blstPublicKey).Uncompress(compressed)
	if blstPublicKey == nil {
		return nil, errors.New("cannot uncompress given public key in bytes")
	}
	if !blstPublicKey.KeyValidate() {
		return nil, errors.New("invalid BLS public key")
	}
	publicKey.p = blstPublicKey
	return publicKey, nil
}

func (publicKey *BLSTPublicKey) ToBytes() []byte {
	return publicKey.p.Compress()
}

func (publicKey *BLSTPublicKey) Equal(other PublicKey) bool {
	return publicKey.p.Equals(other.(*BLSTPublicKey).p)
}

func (signature *BLSTSignature) FromBytes(compressed []byte) (Signature, error) {
	if len(compressed) != SignatureSize {
		return nil, errSignatureSize
	}
	blstSignature := new(blstSignature).Uncompress(compressed)
	if blstSignature == nil {
		return nil, errInvalidSignature
	}
	if !blstSignature.KeyValidate() {
		return nil, errInvalidSignature
	}
	signature.p = blstSignature
	return signature, nil
}

func (signature *BLSTSignature) ToBytes() []byte {
	return signature.p.Compress()
}

func (signature *BLSTSignature) Equal(other Signature) bool {
	return signature.p.Equals(other.(*BLSTSignature).p)
}

func (signature *BLSTSignature) Verify(publicKey PublicKey, message []byte) bool {
	return signature.p.
		Verify(
			blstOptionCheckSignatureSubgroupInVerification,
			publicKey.(*BLSTPublicKey).p,
			blstOptionValidatePublicKeyInVerification,
			message,
			dst,
		)
}

func (signature *BLSTSignature) FastAggregateVerify(publicKeys []PublicKey, message []byte) bool {
	blstPublicKeys := make([]*blstPublicKey, len(publicKeys))
	for i := 0; i < len(publicKeys); i++ {
		blstPublicKeys[i] = publicKeys[i].(*BLSTPublicKey).p
	}
	return signature.p.
		FastAggregateVerify(
			blstOptionCheckSignatureSubgroupInVerification,
			blstPublicKeys,
			message[:],
			dst,
		)
}

func (signature *BLSTSignature) AggregateVerify(publicKeys []PublicKey, messages [][]byte) bool {
	size := len(publicKeys)
	if size == 0 {
		return false
	}
	if len(messages) != size {
		return false
	}
	blstPublicKeys := make([]*blstPublicKey, len(publicKeys))
	for i := 0; i < size; i++ {
		blstPublicKeys[i] = publicKeys[i].(*BLSTPublicKey).p
	}
	return signature.p.
		AggregateVerify(
			blstOptionCheckSignatureSubgroupInVerification,
			blstPublicKeys,
			blstOptionValidatePublicKeyInVerification,
			messages,
			dst,
		)
}

func blstAggregateSignature(signatures []Signature) Signature {
	size := len(signatures)
	blstSignatures := make([]*blstSignature, size)
	for i := 0; i < size; i++ {
		blstSignatures[i] = signatures[i].(*BLSTSignature).p
	}
	aggregatedSignature := new(blst.P2Aggregate)
	aggregatedSignature.Aggregate(blstSignatures, false)
	return &BLSTSignature{aggregatedSignature.ToAffine()}
}

func blstAggregatePublicKey(publicKeys []PublicKey) PublicKey {
	size := len(publicKeys)
	blstPublicKeys := make([]*blstPublicKey, size)
	for i := 0; i < size; i++ {
		blstPublicKeys[i] = publicKeys[i].(*BLSTPublicKey).p
	}
	aggregatedPublicKey := new(blst.P1Aggregate)
	aggregatedPublicKey.Aggregate(blstPublicKeys, false)
	return &BLSTPublicKey{aggregatedPublicKey.ToAffine()}
}
