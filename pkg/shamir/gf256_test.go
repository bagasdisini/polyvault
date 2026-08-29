package shamir

import "testing"

func TestGfMul_Basic(t *testing.T) {
	tests := []struct {
		a, b, want byte
	}{
		{0, 5, 0},
		{1, 5, 5},
		{5, 1, 5},
		{2, 2, 4},
		{0x53, 0xCA, 0x01}, // AES test vector: these should multiply to 1 (inverses)
	}

	for _, tt := range tests {
		got := gfMul(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("gfMul(0x%02x, 0x%02x) = 0x%02x, want 0x%02x", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestGfMul_Commutativity(t *testing.T) {
	for a := range 256 {
		for b := range 256 {
			if gfMul(byte(a), byte(b)) != gfMul(byte(b), byte(a)) {
				t.Errorf("gfMul not commutative: %d * %d", a, b)
			}
		}
	}
}

func TestGfMul_Associativity(t *testing.T) {
	// Test a sample of triples
	for a := range 32 {
		for b := range 32 {
			for c := range 32 {
				left := gfMul(gfMul(byte(a), byte(b)), byte(c))
				right := gfMul(byte(a), gfMul(byte(b), byte(c)))
				if left != right {
					t.Errorf("gfMul not associative: (%d*%d)*%d != %d*(%d*%d)", a, b, c, a, b, c)
				}
			}
		}
	}
}

func TestGfMul_Distributivity(t *testing.T) {
	for a := range 16 {
		for b := range 16 {
			for c := range 16 {
				// a*(b+c) == a*b + a*c
				left := gfMul(byte(a), byte(b)^byte(c))
				right := gfMul(byte(a), byte(b)) ^ gfMul(byte(a), byte(c))
				if left != right {
					t.Errorf("gfMul not distributive: %d*(%d+%d)", a, b, c)
				}
			}
		}
	}
}

func TestGfInv(t *testing.T) {
	// a * a^-1 should equal 1 for all non-zero a
	for a := 1; a < 256; a++ {
		inv := gfInv(byte(a))
		product := gfMul(byte(a), inv)
		if product != 1 {
			t.Errorf("gfInv(0x%02x): a * a^-1 = 0x%02x, want 0x01", a, product)
		}
	}
}

func TestGfDiv(t *testing.T) {
	// a / a should equal 1 for all non-zero a
	for a := 1; a < 256; a++ {
		result := gfDiv(byte(a), byte(a))
		if result != 1 {
			t.Errorf("gfDiv(0x%02x, 0x%02x) = 0x%02x, want 0x01", a, a, result)
		}
	}
}
