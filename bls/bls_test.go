package cross_bls

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"testing"
)

func randPublicKey() PublicKey {
	return RandSecretKey().PublicKey()
}

func randSignature() Signature {
	secretKey := RandSecretKey()
	message := make([]byte, 32)
	_, err := rand.Read(message)
	if err != nil {
		panic(err)
	}
	return secretKey.Sign(message)
}

func TestMain(m *testing.M) {
	_library := flag.String("lib", "none", "select a library")
	flag.Parse()
	library = *_library
	_init()
	os.Exit(m.Run())
}

const n = 100

func TestCross(t *testing.T) {
	initBLST()
	initHerumi()
	initKilic()
	secretKeyBytes := randBLSTSecretKey().ToBytes()
	blstSecretKey, err := blstSecretKeyFromBytes(secretKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	herumiSecretKey, err := herumiSecretKeyFromBytes(secretKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	kilicSecretKey, err := kilicSecretKeyFromBytes(secretKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secretKeyBytes, herumiSecretKey.ToBytes()) {
		t.Fatal("herumi secret key")
	}
	if !bytes.Equal(secretKeyBytes, kilicSecretKey.ToBytes()) {
		t.Fatal("kilic secret key")
	}

	blstPublicKey := blstSecretKey.PublicKey()
	herumiPublicKey := herumiSecretKey.PublicKey()
	kilicPublicKey := kilicSecretKey.PublicKey()

	publicKeyBytes := blstPublicKey.ToBytes()
	if !bytes.Equal(publicKeyBytes, herumiPublicKey.ToBytes()) {
		t.Fatal("herumi public key")
	}
	if !bytes.Equal(publicKeyBytes, kilicPublicKey.ToBytes()) {
		t.Fatal("kilic public key")
	}

	message := []byte("test")
	blstSignature := blstSecretKey.Sign(message)
	herumiSignature := herumiSecretKey.Sign(message)
	kilicSignature := kilicSecretKey.Sign(message)

	signatureBytes := blstSignature.ToBytes()
	if !bytes.Equal(signatureBytes, herumiSignature.ToBytes()) {
		t.Fatal("herumi signature")
	}
	if !bytes.Equal(signatureBytes, kilicSignature.ToBytes()) {
		t.Fatal("kilic signature")
	}
}

func TestSecretKeySerialization(t *testing.T) {
	var err error
	_, err = SecretKeyFromBytes(zeroSecretKey)
	if err != errZeroSecretKey {
		t.Fatalf("zero secret key")
	}
	shortSecretKey := make([]byte, 31)
	shortSecretKey[0] = 1
	_, err = SecretKeyFromBytes(shortSecretKey)
	if err != errSecretKeySize {
		t.Fatalf("short secret key")
	}
	longSecretKey := make([]byte, 33)
	longSecretKey[0] = 1
	_, err = SecretKeyFromBytes(longSecretKey)
	if err != errSecretKeySize {
		t.Fatalf("long secret key")
	}
	secretKeyBytes, err := hex.DecodeString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
	if err != nil {
		t.Fatal(err)
	}
	_, err = SecretKeyFromBytes(secretKeyBytes)
	if err != errInvalidSecretKey {
		t.Fatalf("large secret key")
	}
	secretKeyBytes, err = hex.DecodeString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000")
	if err != nil {
		t.Fatal(err)
	}
	secretKey, err := SecretKeyFromBytes(secretKeyBytes)
	if err != nil {
		t.Fatalf("valid secret key must pass")
	}
	if !bytes.Equal(secretKeyBytes, secretKey.ToBytes()) {
		t.Fatalf("serialization failed, a")
	}
	for i := 0; i < n; i++ {
		secretKey1 := RandSecretKey()
		if bytes.Equal(secretKey1.ToBytes(), zeroSecretKey) {
			t.Fatalf("random generates zero secret key lib: %s", library)
		}
		secretKey2, err := SecretKeyFromBytes(secretKey1.ToBytes())
		if err != nil {
			t.Fatalf("serialization failed, b")
		}
		if !secretKey1.Equal(secretKey2) {
			t.Fatalf("serialization failed, c")
		}
	}
}

func TestPublicKeySerialization(t *testing.T) {

	var err error
	_, err = PublicKeyFromBytes(zeroPublicKey)
	if err != errZeroPublicKey {
		t.Fatalf("zero public key")
	}
	_, err = PublicKeyFromBytes(infinitePublicKey)
	if err != errInfinitePublicKey {
		t.Fatalf("infinite public key")
	}
	shortPublicKey := make([]byte, 47)
	shortPublicKey[0] = 1
	_, err = PublicKeyFromBytes(shortPublicKey)
	if err != errPublicKeySize {
		t.Fatalf("short public key")
	}
	longPublicKey := make([]byte, 49)
	longPublicKey[0] = 1
	_, err = PublicKeyFromBytes(longPublicKey)
	if err != errPublicKeySize {
		t.Fatalf("long public key")
	}
	for i := 0; i < n; i++ {
		publicKey1 := randPublicKey()
		publicKey2, err := PublicKeyFromBytes(publicKey1.ToBytes())
		if err != nil {
			t.Fatalf("serialization failed, b")
		}
		if !publicKey1.Equal(publicKey2) {
			t.Fatalf("serialization failed, c")
		}
	}

}

func TestSignatureSerialization(t *testing.T) {

	var err error
	_, err = SignatureFromBytes(zeroSignature)
	if err != errZeroSignature {
		t.Fatalf("zero signature")
	}
	_, err = SignatureFromBytes(infiniteSignature)
	if err != errInfiniteSignature {
		t.Fatalf("infinite signature")
	}
	shortSignature := make([]byte, 95)
	shortSignature[0] = 1
	_, err = SignatureFromBytes(shortSignature)
	if err != errSignatureSize {
		t.Fatalf("short signature")
	}
	longSignature := make([]byte, 97)
	longSignature[0] = 1
	_, err = SignatureFromBytes(longSignature)
	if err != errSignatureSize {
		t.Fatalf("long signature")
	}
	for i := 0; i < n; i++ {
		signature1 := randSignature()
		signature2, err := SignatureFromBytes(signature1.ToBytes())
		if err != nil {
			t.Fatalf("serialization failed, b")
		}
		if !signature1.Equal(signature2) {
			t.Fatalf("serialization failed, c")
		}
	}

}

func TestVerify(t *testing.T) {
	message1, message2 := []byte("test 1"), []byte("test 2")
	secretKey1 := RandSecretKey()
	publicKey1 := secretKey1.PublicKey()
	secretKey2 := RandSecretKey()
	publicKey2 := secretKey2.PublicKey()

	signature := secretKey1.Sign(message1)

	if !signature.Verify(publicKey1, message1) {
		t.Fatalf("must be verified")
	}
	if signature.Verify(publicKey1, message2) {
		t.Fatalf("must not be verified")
	}
	if signature.Verify(publicKey2, message1) {
		t.Fatalf("must not be verified")
	}

}

func TestFastAggregateVerify(t *testing.T) {

	const nPublicKeys = 10

	message1, message2 := []byte("test 1"), []byte("test 2")

	publicKeys := make([]PublicKey, nPublicKeys)
	signatures := make([]Signature, nPublicKeys)
	missingPublicKeys := make([]PublicKey, nPublicKeys-1)
	missingSignatures := make([]Signature, nPublicKeys-1)
	for i := 0; i < nPublicKeys; i++ {
		secretKey := RandSecretKey()
		publicKey := secretKey.PublicKey()
		signature := secretKey.Sign(message1)

		signatures[i] = signature
		publicKeys[i] = publicKey
		if i != nPublicKeys-1 {
			missingPublicKeys[i] = publicKey
			missingSignatures[i] = signature
		}
	}

	aggregatedSignature := AggreagateSignatures(signatures)
	badAggregatedSignature := AggreagateSignatures(missingSignatures)

	if !aggregatedSignature.FastAggregateVerify(publicKeys, message1) {
		t.Fatalf("must be verified")
	}
	if aggregatedSignature.FastAggregateVerify(publicKeys, message2) {
		t.Fatalf("must not be verified")
	}
	if aggregatedSignature.FastAggregateVerify(missingPublicKeys, message1) {
		t.Fatalf("must not be verified")
	}
	if badAggregatedSignature.FastAggregateVerify(publicKeys, message1) {
		t.Fatalf("must not be verified")
	}
}

func TestAggregateVerify(t *testing.T) {
	const nPublicKeys = 10
	messages1 := make([][]byte, nPublicKeys)
	messages2 := make([][]byte, nPublicKeys)
	publicKeys := make([]PublicKey, nPublicKeys)
	signatures := make([]Signature, nPublicKeys)
	missingSignatures := make([]Signature, nPublicKeys-1)
	for i := 0; i < nPublicKeys; i++ {
		message1 := make([]byte, 32)
		rand.Read(message1)
		message2 := make([]byte, 32)
		rand.Read(message2)
		secretKey := RandSecretKey()
		publicKey := secretKey.PublicKey()
		signature := secretKey.Sign(message1)

		messages1[i] = message1
		messages2[i] = message2
		signatures[i] = signature
		publicKeys[i] = publicKey
		if i != nPublicKeys-1 {
			missingSignatures[i] = signature
		}
	}
	aggregatedSignature := AggreagateSignatures(signatures)
	badAggregatedSignature := AggreagateSignatures(missingSignatures)

	if !aggregatedSignature.AggregateVerify(publicKeys, messages1) {
		t.Fatalf("must be verified")
	}
	if aggregatedSignature.AggregateVerify(publicKeys, messages2) {
		t.Fatalf("must not be verified")
	}
	if badAggregatedSignature.AggregateVerify(publicKeys, messages1) {
		t.Fatalf("must not be verified")
	}
}

func BenchmarkVerify(t *testing.B) {
	message := []byte("test 1")
	secretKey := RandSecretKey()
	publicKey := secretKey.PublicKey()
	signature := secretKey.Sign(message)
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		signature.Verify(publicKey, message)
	}
}

func BenchmarkFastAggregateVerify(t *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.B) {
			message := []byte("test")
			publicKeys := make([]PublicKey, n)
			signatures := make([]Signature, n)
			for i := 0; i < n; i++ {
				secretKey := RandSecretKey()
				publicKey := secretKey.PublicKey()
				signature := secretKey.Sign(message)
				signatures[i] = signature
				publicKeys[i] = publicKey
			}
			aggregatedSignature := AggreagateSignatures(signatures)
			t.ResetTimer()
			for i := 0; i < t.N; i++ {
				aggregatedSignature.FastAggregateVerify(publicKeys, message)
			}
		})
	}
}

func BenchmarkAggregateVerify(t *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.B) {
			messages := make([][]byte, n)
			publicKeys := make([]PublicKey, n)
			signatures := make([]Signature, n)
			for i := 0; i < n; i++ {
				message := make([]byte, 32)
				rand.Read(message)
				secretKey := RandSecretKey()
				publicKey := secretKey.PublicKey()
				signature := secretKey.Sign(message)
				signatures[i] = signature
				publicKeys[i] = publicKey
				messages[i] = message
			}
			aggregatedSignature := AggreagateSignatures(signatures)
			t.ResetTimer()
			for i := 0; i < t.N; i++ {
				aggregatedSignature.AggregateVerify(publicKeys, messages)
			}
		})
	}
}
