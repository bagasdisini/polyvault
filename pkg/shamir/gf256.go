package shamir

// GF(256) arithmetic using the irreducible polynomial x^8 + x^4 + x^3 + x + 1
// (0x11B at the bit level, same as AES).

// gfMul multiplies two elements in GF(256).
func gfMul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b // reduction polynomial
		}
		b >>= 1
	}
	return p
}

// gfInv returns the multiplicative inverse in GF(256).
// Uses Fermat's little theorem: a^(-1) = a^(254) in GF(256).
func gfInv(a byte) byte {
	if a == 0 {
		return 0 // technically undefined, but return 0
	}
	// a^254 = a^(2+4+8+16+32+64+128)
	var result byte = a
	for i := 0; i < 7; i++ {
		result = gfMul(result, result) // square
		if (254>>(uint(i)+1))&1 != 0 {
			result = gfMul(result, a)
		}
	}
	return result
}

// gfDiv divides a by b in GF(256).
func gfDiv(a, b byte) byte {
	return gfMul(a, gfInv(b))
}
