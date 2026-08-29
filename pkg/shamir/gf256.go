package shamir

// GF(256) arithmetic using the irreducible polynomial x^8 + x^4 + x^3 + x + 1
// (0x11B at the bit level, same as AES).

// gfMul multiplies two elements in GF(256).
func gfMul(a, b byte) byte {
	var p byte
	for range 8 {
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
		return 0 // technically undefined, but we return 0
	}
	// Square-and-multiply: compute a^254
	// 254 = 11111110 in binary
	var result byte = 1
	exp := byte(254)
	base := a

	for exp > 0 {
		if exp&1 != 0 {
			result = gfMul(result, base)
		}
		base = gfMul(base, base)
		exp >>= 1
	}
	return result
}

// gfDiv divides a by b in GF(256).
func gfDiv(a, b byte) byte {
	return gfMul(a, gfInv(b))
}
