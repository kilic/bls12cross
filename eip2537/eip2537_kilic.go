package cross_eip2537

import (
	kilic "github.com/kilic/bls12-381"
)

type kilicPointG1 = kilic.PointG1
type kilicPointG2 = kilic.PointG2
type kilicScalar = kilic.Fr

func KilicG1Add(input []byte) ([]byte, error) {
	// Implements EIP-2537 G1Add precompile.
	// > G1 addition call expects `256` bytes as an input that is interpreted as byte concatenation of two G1 points (`128` bytes each).
	// > Output is an encoding of addition operation result - single G1 point (`128` bytes).
	if len(input) != 256 {
		return nil, errEIP2537InvalidInputLength
	}
	var err error
	var p0, p1 *kilicPointG1

	// Initialize G1
	g := kilic.NewG1()

	// Decode G1 point p_0
	p0Bytes, err := decodeG1Point(input[:128])
	if err != nil {
		return nil, err
	}
	if p0, err = g.FromBytes(p0Bytes); err != nil {
		return nil, err
	}
	// Decode G1 point p_1
	p1Bytes, err := decodeG1Point(input[128:])
	if err != nil {
		return nil, err
	}
	if p1, err = g.FromBytes(p1Bytes); err != nil {
		return nil, err
	}

	// Compute r = p_0 + p_1
	r := g.New()
	g.Add(r, p0, p1)

	// Encode the G1 point result into 128 bytes
	return encodeG1Point(g.ToBytes(r)), nil
}

func KilicG1Mul(input []byte) ([]byte, error) {
	// Implements EIP-2537 G1Mul precompile.
	// > G1 multiplication call expects `160` bytes as an input that is interpreted as byte concatenation of encoding of G1 point (`128` bytes) and encoding of a scalar value (`32` bytes).
	// > Output is an encoding of multiplication operation result - single G1 point (`128` bytes).
	if len(input) != 160 {
		return nil, errEIP2537InvalidInputLength
	}
	var err error
	var p0 *kilicPointG1

	// Initialize G1
	g := kilic.NewG1()

	// Decode G1 point
	pointBytes, err := decodeG1Point(input[:128])
	if err != nil {
		return nil, err
	}
	if p0, err = g.FromBytes(pointBytes); err != nil {
		return nil, err
	}
	// Decode scalar value
	e := new(kilicScalar).FromBytes(input[128:])

	// Compute r = e * p_0
	r := g.New()
	g.MulScalar(r, p0, e)

	// Encode the G1 point into 128 bytes
	return encodeG1Point(g.ToBytes(r)), nil
}

func KilicG1MultiExp(input []byte) ([]byte, error) {
	// Implements EIP-2537 G1MultiExp precompile.
	// G1 multiplication call expects `160*k` bytes as an input that is interpreted as byte concatenation of `k` slices each of them being a byte concatenation of encoding of G1 point (`128` bytes) and encoding of a scalar value (`32` bytes).
	// Output is an encoding of multiexponentiation operation result - single G1 point (`128` bytes).
	k := len(input) / 160
	if len(input) == 0 || len(input)%160 != 0 {
		return nil, errEIP2537InvalidInputLength
	}

	points := make([]*kilicPointG1, k)
	scalars := make([]*kilicScalar, k)

	// Initialize G1
	g := kilic.NewG1()

	// Decode point scalar pairs
	for i := 0; i < k; i++ {
		off := 160 * i
		t0, t1, t2 := off, off+128, off+160
		// Decode G1 point
		pointBytes, err := decodeG1Point(input[t0:t1])
		if err != nil {
			return nil, err
		}
		points[i], err = g.FromBytes(pointBytes)
		if err != nil {
			return nil, err
		}
		// Decode scalar value
		scalars[i] = new(kilicScalar).FromBytes(input[t1:t2])
	}

	// Compute r = e_0 * p_0 + e_1 * p_1 + ... + e_(k-1) * p_(k-1)
	r := g.New()
	g.MultiExp(r, points, scalars)

	// Encode the G1 point to 128 bytes
	return encodeG1Point(g.ToBytes(r)), nil
}

func KilicG2Add(input []byte) ([]byte, error) {
	// Implements EIP-2537 G2Add precompile.
	// > G2 addition call expects `512` bytes as an input that is interpreted as byte concatenation of two G2 points (`256` bytes each).
	// > Output is an encoding of addition operation result - single G2 point (`256` bytes).
	if len(input) != 512 {
		return nil, errEIP2537InvalidInputLength
	}
	var err error
	var p0, p1 *kilicPointG2

	// Initialize G2
	g := kilic.NewG2()
	r := g.New()

	// Decode G2 point p_0
	p0Bytes, err := decodeG2Point(input[:256])
	if err != nil {
		return nil, err
	}
	if p0, err = g.FromBytes(p0Bytes); err != nil {
		return nil, err
	}
	// Decode G2 point p_1
	p1Bytes, err := decodeG2Point(input[256:])
	if err != nil {
		return nil, err
	}
	if p1, err = g.FromBytes(p1Bytes); err != nil {
		return nil, err
	}

	// Compute r = p_0 + p_1
	g.Add(r, p0, p1)

	// Encode the G2 point into 256 bytes
	return encodeG2Point(g.ToBytes(r)), nil

}

func KilicG2Mul(input []byte) ([]byte, error) {
	// Implements EIP-2537 G2MUL precompile logic.
	// > G2 multiplication call expects `288` bytes as an input that is interpreted as byte concatenation of encoding of G2 point (`256` bytes) and encoding of a scalar value (`32` bytes).
	// > Output is an encoding of multiplication operation result - single G2 point (`256` bytes).
	if len(input) != 288 {
		return nil, errEIP2537InvalidInputLength
	}
	var p0 *kilicPointG2

	// Initialize G2
	g := kilic.NewG2()

	// Decode G2 point
	pointBytes, err := decodeG2Point(input[:256])
	if err != nil {
		return nil, err
	}
	if p0, err = g.FromBytes(pointBytes); err != nil {
		return nil, err
	}
	// Decode scalar value
	e := new(kilicScalar).FromBytes(input[256:])

	// Compute r = e * p_0
	r := g.New()
	g.MulScalar(r, p0, e)

	// Encode the G2 point into 256 bytes
	return encodeG2Point(g.ToBytes(r)), nil
}

func KilicG2MultiExp(input []byte) ([]byte, error) {
	// Implements EIP-2537 G2MultiExp precompile logic
	// > G2 multiplication call expects `288*k` bytes as an input that is interpreted as byte concatenation of `k` slices each of them being a byte concatenation of encoding of G2 point (`256` bytes) and encoding of a scalar value (`32` bytes).
	// > Output is an encoding of multiexponentiation operation result - single G2 point (`256` bytes).
	k := len(input) / 288
	if len(input) == 0 || len(input)%288 != 0 {
		return nil, errEIP2537InvalidInputLength
	}
	points := make([]*kilicPointG2, k)
	scalars := make([]*kilicScalar, k)

	// Initialize G2
	g := kilic.NewG2()

	// Decode point scalar pairs
	for i := 0; i < k; i++ {
		off := 288 * i
		t0, t1, t2 := off, off+256, off+288
		// Decode G1 point
		pointBytes, err := decodeG2Point(input[t0:t1])
		if err != nil {
			return nil, err
		}
		points[i], err = g.FromBytes(pointBytes)
		if err != nil {
			return nil, err
		}
		// Decode scalar value
		scalars[i] = new(kilicScalar).FromBytes(input[t1:t2])
	}

	// Compute r = e_0 * p_0 + e_1 * p_1 + ... + e_(k-1) * p_(k-1)
	r := g.New()
	g.MultiExp(r, points, scalars)

	// Encode the G2 point to 256 bytes.
	return encodeG2Point(g.ToBytes(r)), nil
}

func KilicPairing(input []byte) ([]byte, error) {
	// Implements EIP-2537 Pairing precompile logic.
	// > Pairing call expects `384*k` bytes as an inputs that is interpreted as byte concatenation of `k` slices. Each slice has the following structure:
	// > - `128` bytes of G1 point encoding
	// > - `256` bytes of G2 point encoding
	// > Output is a `32` bytes where last single byte is `0x01` if pairing result is equal to multiplicative identity in a pairing target field and `0x00` otherwise
	// > (which is equivalent of Big Endian encoding of Solidity values `uint256(1)` and `uin256(0)` respectively).
	k := len(input) / 384
	if len(input) == 0 || len(input)%384 != 0 {
		return nil, errEIP2537InvalidInputLength
	}

	// Initialize BLS12-381 pairing engine
	e := kilic.NewEngine()
	g1, g2 := e.G1, e.G2

	// Decode pairs
	for i := 0; i < k; i++ {
		off := 384 * i
		t0, t1, t2 := off, off+128, off+384

		// Decode G1 point
		p1Bytes, err := decodeG1Point(input[t0:t1])
		if err != nil {
			return nil, err
		}
		p1, err := g1.FromBytes(p1Bytes)
		if err != nil {
			return nil, err
		}
		// Decode G2 point
		p2Bytes, err := decodeG2Point(input[t1:t2])
		if err != nil {
			return nil, err
		}
		p2, err := g2.FromBytes(p2Bytes)
		if err != nil {
			return nil, err
		}

		// 'point is on curve' check already done,
		// Here we need to apply subgroup checks.
		if !g1.InCorrectSubgroup(p1) {
			return nil, errEIP2537G1PointSubgroup
		}
		if !g2.InCorrectSubgroup(p2) {
			return nil, errEIP2537G2PointSubgroup
		}

		// Update pairing engine with G1 and G2 ponits
		e.AddPair(p1, p2)
	}
	// Prepare 32 byte output
	out := make([]byte, 32)

	// Compute pairing and set the result
	if e.Check() {
		out[31] = 1
	}
	return out, nil
}

func KilicMapG1(input []byte) ([]byte, error) {
	// Implements EIP-2537 Map_To_G1 precompile.
	// > Field-to-curve call expects `64` bytes an an input that is interpreted as a an element of the base field.
	// > Output of this call is `128` bytes and is G1 point following respective encoding rules.
	if len(input) != 64 {
		return nil, errEIP2537InvalidInputLength
	}

	// Decode input field element
	fe, err := decodeFieldElement(input)
	if err != nil {
		return nil, err
	}

	// Initialize G1
	g := kilic.NewG1()

	// Compute mapping
	r, err := g.MapToCurve(fe)
	if err != nil {
		return nil, err
	}

	// Encode the G1 point to 128 bytes
	return encodeG1Point(g.ToBytes(r)), nil
}

func KilicMapG2(input []byte) ([]byte, error) {
	// Implements EIP-2537 Map_FP2_TO_G2 precompile logic.
	// > Field-to-curve call expects `128` bytes an an input that is interpreted as a an element of the quadratic extension field.
	// > Output of this call is `256` bytes and is G2 point following respective encoding rules.
	if len(input) != 128 {
		return nil, errEIP2537InvalidInputLength
	}

	// Decode input field element
	fe := make([]byte, 96)
	c0, err := decodeFieldElement(input[:64])
	if err != nil {
		return nil, err
	}
	copy(fe[48:], c0)
	c1, err := decodeFieldElement(input[64:])
	if err != nil {
		return nil, err
	}
	copy(fe[:48], c1)

	// Initialize G2
	g := kilic.NewG2()

	// Compute mapping
	r, err := g.MapToCurve(fe)
	if err != nil {
		return nil, err
	}

	// Encode the G2 point to 256 bytes
	return encodeG2Point(g.ToBytes(r)), nil
}
