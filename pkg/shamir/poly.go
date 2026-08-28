package shamir

import "crypto/rand"

// randomPolynomial generates a random polynomial of degree `threshold-1`
// with the given constant term (the secret byte).
func randomPolynomial(constant byte, threshold int) ([]byte, error) {
	poly := make([]byte, threshold)
	poly[0] = constant

	if threshold > 1 {
		coeffs := make([]byte, threshold-1)
		_, err := rand.Read(coeffs)
		if err != nil {
			return nil, err
		}
		copy(poly[1:], coeffs)
	}

	return poly, nil
}

// polyEval evaluates a polynomial at point x using Horner's method.
// All arithmetic is in GF(256).
func polyEval(poly []byte, x byte) byte {
	// Horner's method: a_n*x^n + ... + a_1*x + a_0
	// = ((...((a_n*x + a_{n-1})*x + a_{n-2})*x + ...)*x + a_1)*x + a_0
	result := poly[len(poly)-1]
	for i := len(poly) - 2; i >= 0; i-- {
		result = gfMul(result, x) ^ poly[i]
	}
	return result
}

// lagrangeInterpolate computes f(0) using Lagrange interpolation over GF(256).
// This gives us the secret byte (the constant term of the polynomial).
func lagrangeInterpolate(points []struct{ x, y byte }, at byte) byte {
	var result byte

	for i, pi := range points {
		numerator := byte(1)
		denominator := byte(1)

		for j, pj := range points {
			if i == j {
				continue
			}
			// numerator *= (at - x_j)
			numerator = gfMul(numerator, at^pj.x)
			// denominator *= (x_i - x_j)
			denominator = gfMul(denominator, pi.x^pj.x)
		}

		// term = y_i * numerator / denominator
		term := gfMul(pi.y, gfDiv(numerator, denominator))
		result ^= term
	}

	return result
}
