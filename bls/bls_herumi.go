package cross_bls

import (
	herumi "github.com/herumi/bls-eth-go-binary/bls"
)

type herumiPublicKey = herumi.PublicKey
type herumiSecretKey = herumi.SecretKey
type herumiSignature = herumi.Sign

type HerumiPublicKey struct {
	p *herumiPublicKey
}

type HerumiSecretKey struct {
	s *herumiSecretKey
}

type HerumiSignature struct {
	p *herumiSignature
}

func randHerumiSecretKey() SecretKey {
	secretKey := new(herumi.SecretKey)
	secretKey.SetByCSPRNG()
	return &HerumiSecretKey{secretKey}
}

func herumiSecretKeyFromBytes(in []byte) (SecretKey, error) {
	if len(in) != SecretKeySize {
		return nil, errSecretKeySize
	}
	secretKey := new(herumi.SecretKey)
	err := secretKey.Deserialize(in)
	if err != nil {
		return nil, errInvalidSecretKey
	}
	return &HerumiSecretKey{secretKey}, nil
}

func (secretKey *HerumiSecretKey) Equal(other SecretKey) bool {
	return secretKey.s.IsEqual(other.(*HerumiSecretKey).s)
}

func (secretKey *HerumiSecretKey) PublicKey() PublicKey {
	return &HerumiPublicKey{secretKey.s.GetPublicKey()}
}

func (secretKey *HerumiSecretKey) Sign(message []byte) Signature {
	herumiSignature := secretKey.s.Sign(string(message))
	return &HerumiSignature{herumiSignature}
}

func (secretKey *HerumiSecretKey) ToBytes() []byte {
	return secretKey.s.Serialize()
}

func (publicKey *HerumiPublicKey) FromBytes(compresed []byte) (PublicKey, error) {
	if len(compresed) != PublicKeySize {
		return nil, errPublicKeySize
	}
	herumiPublicKey := new(herumiPublicKey)
	if err := herumiPublicKey.Deserialize(compresed); err != nil {
		return nil, err
	}
	if !herumiPublicKey.IsValidOrder() {
		return nil, errInvalidPublicKey
	}
	if herumiPublicKey.IsZero() {
		return nil, errZeroPublicKey
	}
	publicKey.p = herumiPublicKey
	return publicKey, nil
}

func (publicKey *HerumiPublicKey) ToBytes() []byte {
	return publicKey.p.Serialize()
}

func (publicKey *HerumiPublicKey) Equal(other PublicKey) bool {
	return publicKey.p.IsEqual(other.(*HerumiPublicKey).p)
}

func (signature *HerumiSignature) FromBytes(compresed []byte) (Signature, error) {
	if len(compresed) != SignatureSize {
		return nil, errSignatureSize
	}
	herumiSignature := new(herumiSignature)
	if err := herumiSignature.Deserialize(compresed); err != nil {
		return nil, err
	}
	if !herumiSignature.IsValidOrder() {
		return nil, errInvalidSignature
	}
	if herumiSignature.IsZero() {
		return nil, errZeroSignature
	}
	signature.p = herumiSignature
	return signature, nil
}

func (signature *HerumiSignature) ToBytes() []byte {
	return signature.p.Serialize()
}

func (signature *HerumiSignature) Equal(other Signature) bool {
	return signature.p.IsEqual(other.(*HerumiSignature).p)
}

func (signature *HerumiSignature) Verify(publicKey PublicKey, message []byte) bool {
	return signature.p.
		Verify(
			publicKey.(*HerumiPublicKey).p,
			string(message),
		)
}

func (signature *HerumiSignature) FastAggregateVerify(publicKeys []PublicKey, message []byte) bool {
	if len(publicKeys) == 0 {
		return false
	}
	herumiPublicKeys := make([]herumiPublicKey, len(publicKeys))
	for i := 0; i < len(publicKeys); i++ {
		herumiPublicKeys[i] = *publicKeys[i].(*HerumiPublicKey).p
	}
	return signature.p.
		FastAggregateVerify(
			herumiPublicKeys,
			message[:],
		)
}

func (signature *HerumiSignature) AggregateVerify(publicKeys []PublicKey, messages [][]byte) bool {
	size := len(publicKeys)
	if size == 0 {
		return false
	}
	if len(messages) != size {
		return false
	}
	herumiPublicKeys := make([]herumiPublicKey, size)
	_messages := []byte{}
	for i := 0; i < size; i++ {
		herumiPublicKeys[i] = *publicKeys[i].(*HerumiPublicKey).p
		_messages = append(_messages, messages[i][:]...)
	}
	return signature.p.
		AggregateVerify(
			herumiPublicKeys,
			_messages,
		)
}

func herumiAggregateSignature(signatures []Signature) Signature {
	size := len(signatures)
	herimuSignatures := make([]herumiSignature, size)
	for i := 0; i < size; i++ {
		herimuSignatures[i] = *signatures[i].(*HerumiSignature).p
	}
	aggregatedSignature := new(herumiSignature)
	aggregatedSignature.Aggregate(herimuSignatures)
	return &HerumiSignature{aggregatedSignature}
}

func herumiAggregatePublicKey(publicKeys []PublicKey) PublicKey {
	size := len(publicKeys)
	aggregatedPublicKey := new(herumiPublicKey)
	for i := 0; i < size; i++ {
		aggregatedPublicKey.Add(publicKeys[i].(*HerumiPublicKey).p)
	}
	return &HerumiPublicKey{aggregatedPublicKey}
}
