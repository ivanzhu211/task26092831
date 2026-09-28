package usdz

import (
	"bytes"
	"testing"
)

// bigValidPackage 构造一个接近 50 MiB 的合规包。
func bigValidPackage() []byte {
	pattern := bytes.Repeat([]byte("texture-block-"), 1<<16)
	content := bytes.Repeat(pattern, 56)[:48<<20] // 取 48 MiB
	entries := []zentry{
		{name: "scene.usda", content: []byte("#usda 1.0\n")},
		{name: "tex/big.png", content: content},
	}
	return buildZip(entries, nil, false)
}

func BenchmarkValidate50MiB(b *testing.B) {
	data := bigValidPackage()
	if len(data) > MaxSize {
		b.Fatalf("setup: package too big: %d", len(data))
	}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if issues := Validate(data); len(issues) != 0 {
			b.Fatalf("unexpected issues: %v", issues)
		}
	}
}

func BenchmarkNormalize50MiB(b *testing.B) {
	// 可修复包：deflate + 未对齐，解压后约 48 MiB。
	pattern := bytes.Repeat([]byte("texture-block-"), 1<<16)
	content := bytes.Repeat(pattern, 56)[:48<<20]
	entries := []zentry{
		{name: "scene.usda", content: []byte("#usda 1.0\n")},
		{name: "tex/big.png", content: content, method: 8, noAlign: true},
	}
	data := buildZip(entries, nil, false)
	if len(data) > MaxSize {
		b.Fatalf("setup: input too big: %d", len(data))
	}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, issues := Normalize(data)
		if len(issues) != 0 {
			b.Fatalf("unexpected issues: %v", issues)
		}
		if len(out) > MaxSize {
			b.Fatal("output too big")
		}
	}
}
