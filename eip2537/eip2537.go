package cross_eip2537

import "errors"

func decodeFieldElement(in []byte) ([]byte, error) {
	if len(in) != 64 {
		return nil, errors.New("invalid field element length")
	}
	// check top bytes
	for i := 0; i < 16; i++ {
		if in[i] != byte(0x00) {
			return nil, errors.New("invalid field element top bytes")
		}
	}
	out := make([]byte, 48)
	copy(out[:], in[16:])
	return out, nil
}

func decodeG1Point(in []byte) ([]byte, error) {
	if len(in) != 128 {
		return nil, errors.New("invalid g1 point length")
	}
	pointBytes := make([]byte, 96)
	// decode x
	xBytes, err := decodeFieldElement(in[:64])
	if err != nil {
		return nil, err
	}
	// decode y
	yBytes, err := decodeFieldElement(in[64:])
	if err != nil {
		return nil, err
	}
	copy(pointBytes[:48], xBytes)
	copy(pointBytes[48:], yBytes)
	return pointBytes, nil
}

// encodeG1Point encodes a point into 128 bytes.
func encodeG1Point(outRaw []byte) []byte {
	out := make([]byte, 128)
	// encode x
	copy(out[16:], outRaw[:48])
	// encode y
	copy(out[64+16:], outRaw[48:])
	return out
}

func encodeG2Point(outRaw []byte) []byte {
	// outRaw is 96 bytes
	out := make([]byte, 256)
	// encode x
	copy(out[16:16+48], outRaw[48:96])
	copy(out[80:80+48], outRaw[:48])
	// encode y
	copy(out[144:144+48], outRaw[144:])
	copy(out[208:208+48], outRaw[96:144])
	return out
}

func decodeG2Point(in []byte) ([]byte, error) {
	if len(in) != 256 {
		return nil, errors.New("invalid g2 point length")
	}
	pointBytes := make([]byte, 192)
	x0Bytes, err := decodeFieldElement(in[:64])
	if err != nil {
		return nil, err
	}
	x1Bytes, err := decodeFieldElement(in[64:128])
	if err != nil {
		return nil, err
	}
	y0Bytes, err := decodeFieldElement(in[128:192])
	if err != nil {
		return nil, err
	}
	y1Bytes, err := decodeFieldElement(in[192:])
	if err != nil {
		return nil, err
	}
	copy(pointBytes[:48], x1Bytes)
	copy(pointBytes[48:96], x0Bytes)
	copy(pointBytes[96:144], y1Bytes)
	copy(pointBytes[144:192], y0Bytes)
	return pointBytes, nil
}
