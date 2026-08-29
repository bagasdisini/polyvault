package shamir

import "testing"

func BenchmarkSplit(b *testing.B) {
	secret := make([]byte, 256)
	for i := range secret {
		secret[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Split(secret, 3, 5)
	}
}

func BenchmarkCombine(b *testing.B) {
	secret := make([]byte, 256)
	for i := range secret {
		secret[i] = byte(i)
	}
	shares, _ := Split(secret, 3, 5)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Combine(shares[:3])
	}
}

func BenchmarkGfMul(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gfMul(byte(i), byte(i+1))
	}
}

func BenchmarkGfInv(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gfInv(byte(i%255 + 1))
	}
}
