package main

import (
	"testing"
)

const succeed = "\u2713"
const failed = "\u2717"

func BenchmarkMainTest(b *testing.B) {
	for i := 0; i < b.N; i++ {
		main()
	}
}
