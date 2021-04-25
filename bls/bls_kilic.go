package cross_bls

import (
	"crypto/rand"

	kilic "github.com/kilic/bls12-381"
)

type kilicPublicKey = kilic.PointG1
type kilicSecretKey = kilic.Fr
type kilicSignature = kilic.PointG2

type KilicPublicKey struct {
	p *kilicPublicKey
}

type KilicSecretKey struct {
	s *kilicSecretKey
}

type KilicSignature struct {
	p *kilicSignature
}

var kilicGroupOrder *kilicSecretKey

func randKilicSecretKey() SecretKey {
	s, _ := new(kilic.Fr).Rand(rand.Reader)
	return &KilicSecretKey{s}
}

func kilicSecretKeyFromBytes(in []byte) (SecretKey, error) {
	if len(in) != SecretKeySize {
		return nil, errSecretKeySize
	}
	s := new(kilicSecretKey).FromBytes(in)
	if s.Cmp(kilicGroupOrder) != -1 {
		return nil, errInvalidSecretKey
	}
	return &KilicSecretKey{s}, nil
}

func (secretKey *KilicSecretKey) Equal(other SecretKey) bool {
	return secretKey.s.Equal(other.(*KilicSecretKey).s)
}

func (secretKey *KilicSecretKey) PublicKey() PublicKey {
	g := kilic.NewG1()
	publicKey := g.New()
	g.MulScalar(publicKey, g.One(), secretKey.s)
	return &KilicPublicKey{publicKey}
}

func (secretKey *KilicSecretKey) Sign(message []byte) Signature {
	g := kilic.NewG2()
	M, err := g.HashToCurve(message, dst)
	if err != nil {
		return nil
	}
	signature := g.New()
	g.MulScalar(signature, M, secretKey.s)
	return &KilicSignature{signature}
}

func (secretKey *KilicSecretKey) ToBytes() []byte {
	return secretKey.s.ToBytes()
}

func (publicKey *KilicPublicKey) FromBytes(compressed []byte) (PublicKey, error) {
	if len(compressed) != PublicKeySize {
		return nil, errPublicKeySize
	}
	g := kilic.NewG1()
	kilicPublicKey, err := g.FromCompressed(compressed)
	if err != nil {
		return nil, err
	}
	publicKey.p = kilicPublicKey
	return publicKey, nil
}

func (publicKey *KilicPublicKey) ToBytes() []byte {
	g := kilic.NewG1()
	return g.ToCompressed(publicKey.p)
}

func (publicKey *KilicPublicKey) Equal(other PublicKey) bool {
	g := kilic.NewG1()
	return g.Equal(publicKey.p, (other.(*KilicPublicKey).p))
}

func (signature *KilicSignature) FromBytes(compressed []byte) (Signature, error) {
	if len(compressed) != SignatureSize {
		return nil, errSignatureSize
	}
	g := kilic.NewG2()
	kilicSignature, err := g.FromCompressed(compressed)
	if err != nil {
		return nil, err
	}
	signature.p = kilicSignature
	return signature, nil
}

func (signature *KilicSignature) ToBytes() []byte {
	g := kilic.NewG2()
	return g.ToCompressed(signature.p)
}

func (signature *KilicSignature) Equal(other Signature) bool {
	g := kilic.NewG2()
	return g.Equal(signature.p, (other.(*KilicSignature).p))
}

func (signature *KilicSignature) Verify(publicKey PublicKey, message []byte) bool {
	e := kilic.NewEngine()
	M, err := e.G2.HashToCurve(message, dst)
	if err != nil {
		return false
	}
	e.AddPair((publicKey.(*KilicPublicKey).p), M)
	e.AddPairInv(e.G1.One(), signature.p)
	return e.Check()
}

func (signature *KilicSignature) FastAggregateVerify(publicKeys []PublicKey, message []byte) bool {
	e := kilic.NewEngine()
	M, err := e.G2.HashToCurve(message, dst)
	if err != nil {
		return false
	}
	aggregated := kilicAggregatePublicKey(publicKeys, e.G1)
	e.AddPair((aggregated.(*KilicPublicKey).p), M)
	e.AddPairInv(e.G1.One(), signature.p)
	return e.Check()
}

func (signature *KilicSignature) AggregateVerify(publicKeys []PublicKey, messages [][]byte) bool {
	if len(publicKeys) == 0 {
		return false
	}
	if len(messages) != len(publicKeys) {
		return false
	}
	e := kilic.NewEngine()
	e.AddPairInv(e.G1.One(), signature.p)
	for i := 0; i < len(messages); i++ {
		M, err := e.G2.HashToCurve(messages[i], dst)
		if err != nil {
			return false
		}
		e.AddPair(publicKeys[i].(*KilicPublicKey).p, M)
	}
	return e.Check()

}

func kilicAggregatePublicKey(publicKeys []PublicKey, g *kilic.G1) PublicKey {
	if g == nil {
		g = kilic.NewG1()
	}
	if len(publicKeys) == 0 {
		return &KilicPublicKey{g.Zero()}
	}
	aggregated := new(kilicPublicKey).Set(publicKeys[0].(*KilicPublicKey).p)
	for i := 1; i < len(publicKeys); i++ {
		g.Add(aggregated, aggregated, publicKeys[i].(*KilicPublicKey).p)
	}
	return &KilicPublicKey{aggregated}
}

func kilicAggregateSignature(signatures []Signature, g *kilic.G2) Signature {
	if g == nil {
		g = kilic.NewG2()
	}
	if len(signatures) == 0 {
		return &KilicSignature{g.Zero()}
	}
	aggregated := new(kilicSignature).Set(signatures[0].(*KilicSignature).p)
	for i := 1; i < len(signatures); i++ {
		g.Add(aggregated, aggregated, signatures[i].(*KilicSignature).p)
	}
	return &KilicSignature{aggregated}
}
