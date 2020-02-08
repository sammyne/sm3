package sm3

import "math/bits"

func block(dig *digest, p []byte) {
	var w [132]uint32
	h0, h1, h2, h3, h4, h5, h6, h7 := dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4], dig.h[5], dig.h[6], dig.h[7]

	for len(p) >= chunk {
		// expand the message block
		// Can interlace the computation of w with the
		// rounds below if needed for speed.
		for i := 0; i < 16; i++ {
			j := i * 4
			w[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
		}
		for i := 16; i < 68; i++ {
			w[i] = p1(w[i-16]^w[i-9]^bits.RotateLeft32(w[i-3], 15)) ^
				bits.RotateLeft32(w[i-13], 7) ^
				w[i-6]
		}
		for i := 0; i < 64; i++ {
			w[i+68] = w[i] ^ w[i+4]
		}

		a, b, c, d, e, f, g, h := h0, h1, h2, h3, h4, h5, h6, h7

		// FF(x,y,z)=x ^ y ^ z
		// GG(x,y,z)=x ^ y ^ z
		for i := 0; i < 16; i++ {
			v := bits.RotateLeft32(a, 12)

			ss1 := bits.RotateLeft32(v+e+bits.RotateLeft32(t0, i), 7)
			ss2 := ss1 ^ v

			tt1 := (a ^ b ^ c) + d + ss2 + w[i+68]
			tt2 := (e ^ f ^ g) + h + ss1 + w[i]

			a, b, c, d, e, f, g, h = tt1, a, bits.RotateLeft32(b, 9), c, p0(tt2), e,
				bits.RotateLeft32(f, 19), g
		}

		// FF(x,y,z)=(x & y) | (x & z) | (y & z)
		// GG(x,y,z)=(x & y) | (^x & z)
		for i := 16; i < 64; i++ {
			v := bits.RotateLeft32(a, 12)

			ss1 := bits.RotateLeft32(v+e+bits.RotateLeft32(t1, i%32), 7)
			ss2 := ss1 ^ v

			tt1 := ((a & b) | (a & c) | (b & c)) + d + ss2 + w[i+68]
			tt2 := ((e & f) | ((^e) & g)) + h + ss1 + w[i]

			a, b, c, d, e, f, g, h = tt1, a, bits.RotateLeft32(b, 9), c, p0(tt2), e,
				bits.RotateLeft32(f, 19), g
		}

		h0 ^= a
		h1 ^= b
		h2 ^= c
		h3 ^= d
		h4 ^= e
		h5 ^= f
		h6 ^= g
		h7 ^= h

		p = p[chunk:]
	}

	dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4], dig.h[5], dig.h[6], dig.h[7] = h0, h1, h2, h3, h4, h5, h6, h7
}

func p0(x uint32) uint32 {
	return x ^ bits.RotateLeft32(x, 9) ^ bits.RotateLeft32(x, 17)
}

func p1(x uint32) uint32 {
	return x ^ bits.RotateLeft32(x, 15) ^ bits.RotateLeft32(x, 23)
}
