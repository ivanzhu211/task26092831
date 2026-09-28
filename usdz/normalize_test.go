package usdz

import (
	"archive/zip"
	"bytes"
	"io"
	"reflect"
	"testing"
)

// fixablePackage 构造一个同时带目录条目、deflate 压缩和未对齐的包。
func fixablePackage() ([]byte, []zentry) {
	entries := []zentry{
		{name: "tex/", content: nil},
		{name: "scene.usda", content: []byte("#usda 1.0\n(def \"root\")"), modTime: 111, modDate: 222},
		{name: "tex/diffuse.png", content: bytes.Repeat([]byte("pngdata"), 500), method: 8, modTime: 333, modDate: 444},
		{name: "tex/normal.png", content: []byte("normals"), noAlign: true, modTime: 555, modDate: 666},
		{name: "audio/bgm.mp3", content: bytes.Repeat([]byte("mp3"), 1000), method: 8, noAlign: true, modTime: 777, modDate: 888},
	}
	return buildZip(entries, nil, false), entries
}

func TestNormalizeFixesAll(t *testing.T) {
	data, _ := fixablePackage()
	issues := Validate(data)
	if !hasReason(issues, ReasonCompressed) || !hasReason(issues, ReasonMisaligned) {
		t.Fatalf("setup: expected fixable issues, got %v", issues)
	}
	out, rest := Normalize(data)
	if len(rest) != 0 {
		t.Fatalf("expected successful normalize, got issues %v", rest)
	}
	if got := Validate(out); len(got) != 0 {
		t.Fatalf("normalized output should be valid, got %v", got)
	}
}

func TestNormalizePreservesEntries(t *testing.T) {
	data, entries := fixablePackage()
	out, rest := Normalize(data)
	if len(rest) != 0 {
		t.Fatalf("normalize failed: %v", rest)
	}

	// 用 Go 标准库解开，逐条比对名字、内容与修改时间。
	zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatalf("stdlib cannot open normalized output: %v", err)
	}
	var want []zentry
	for _, e := range entries {
		if e.name[len(e.name)-1] == '/' {
			continue // 目录条目应被去掉
		}
		want = append(want, e)
	}
	if len(zr.File) != len(want) {
		t.Fatalf("entry count: got %d want %d", len(zr.File), len(want))
	}
	for i, f := range zr.File {
		if f.Name != want[i].name {
			t.Fatalf("entry %d name: got %q want %q", i, f.Name, want[i].name)
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", f.Name, err)
		}
		if !bytes.Equal(content, want[i].content) {
			t.Fatalf("entry %s content mismatch", f.Name)
		}
		if f.Method != 0 {
			t.Fatalf("entry %s should be stored", f.Name)
		}
	}

	// 修改时间保持不变（用本模块解析核对原始 DOS 时间字段）。
	parsed, _ := parseZip(out)
	for i, e := range parsed {
		if e.modTime != want[i].modTime || e.modDate != want[i].modDate {
			t.Fatalf("entry %s modtime changed", e.name)
		}
	}
}

func TestNormalizeDeterministicAndIdempotent(t *testing.T) {
	data, _ := fixablePackage()
	out1, _ := Normalize(data)
	out2, _ := Normalize(data)
	if !bytes.Equal(out1, out2) {
		t.Fatal("same input produced different outputs")
	}
	out3, rest := Normalize(out1)
	if len(rest) != 0 {
		t.Fatalf("re-normalize returned issues: %v", rest)
	}
	if !bytes.Equal(out1, out3) {
		t.Fatal("normalize is not idempotent")
	}
}

func TestNormalizeRemovesDirsOnly(t *testing.T) {
	// 只有目录条目需要清理时，也应产出合规包。
	entries := append([]zentry{{name: "a/"}, {name: "a/b/"}}, validEntries()...)
	data := buildZip(entries, nil, false)
	if issues := Validate(data); len(issues) != 0 {
		t.Fatalf("setup: dirs should not be issues, got %v", issues)
	}
	out, rest := Normalize(data)
	if len(rest) != 0 {
		t.Fatalf("normalize failed: %v", rest)
	}
	parsed, _ := parseZip(out)
	for _, e := range parsed {
		if e.isDir {
			t.Fatalf("directory entry %s survived normalize", e.name)
		}
	}
}

func TestNormalizeRejectsUnfixable(t *testing.T) {
	cases := []struct {
		name   string
		mutate func([]zentry) []zentry
	}{
		{"bad extension", func(e []zentry) []zentry {
			return append(e, zentry{name: "x.obj", content: []byte("x")})
		}},
		{"encrypted", func(e []zentry) []zentry {
			e[0].flags = flagEncrypted
			return e
		}},
		{"unsupported method", func(e []zentry) []zentry {
			e[1].method = 12
			return e
		}},
		{"crc mismatch", func(e []zentry) []zentry {
			e[1].hasCRC = true
			e[1].crc = 1
			return e
		}},
		{"first not layer", func(e []zentry) []zentry {
			e[0], e[1] = e[1], e[0]
			return e
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			entries := c.mutate(validEntries())
			entries[2].method = 8 // 混合一个可修复问题
			data := buildZip(entries, nil, false)
			want := Validate(data)
			out, got := Normalize(data)
			if out != nil {
				t.Fatal("should reject unfixable package")
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("issue list mismatch:\n got %v\nwant %v", got, want)
			}
		})
	}
}

func TestNormalizeTooLargeInput(t *testing.T) {
	entries := []zentry{
		{name: "scene.usda", content: []byte("#usda")},
		{name: "big.png", content: make([]byte, MaxSize)},
	}
	data := buildZip(entries, nil, false)
	out, issues := Normalize(data)
	if out != nil || len(issues) != 1 || issues[0].Reason != ReasonTooLarge {
		t.Fatalf("expected too-large reject, got %v", issues)
	}
}

func TestNormalizeOutputTooLarge(t *testing.T) {
	// 高压缩比：60 MiB 零字节 deflate 后很小，但规范化结果超限。
	entries := []zentry{
		{name: "scene.usda", content: []byte("#usda")},
		{name: "big.wav", content: make([]byte, 60<<20), method: 8},
	}
	data := buildZip(entries, nil, false)
	if len(data) > MaxSize {
		t.Fatal("setup: input should be under limit")
	}
	out, issues := Normalize(data)
	if out != nil || len(issues) != 1 || issues[0].Reason != ReasonTooLarge {
		t.Fatalf("expected too-large reject, got %v", issues)
	}
}

func TestNormalizeZip64AndStreaming(t *testing.T) {
	entries := []zentry{
		{name: "scene.usda", content: []byte("#usda 1.0\n"), dd: true},
		{name: "tex.png", content: bytes.Repeat([]byte("t"), 1000), method: 8, dd: true},
	}
	data := buildZip(entries, []byte("comment PK\x05\x06 tail"), true)
	out, rest := Normalize(data)
	if len(rest) != 0 {
		t.Fatalf("normalize failed: %v", rest)
	}
	if got := Validate(out); len(got) != 0 {
		t.Fatalf("normalized output invalid: %v", got)
	}
	zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatalf("stdlib cannot open: %v", err)
	}
	if len(zr.File) != 2 || zr.File[0].Name != "scene.usda" || zr.File[1].Name != "tex.png" {
		t.Fatalf("unexpected entries: %v", zr.File)
	}
}

func TestNormalizeAlignment64(t *testing.T) {
	data, _ := fixablePackage()
	out, _ := Normalize(data)
	parsed, _ := parseZip(out)
	for _, e := range parsed {
		if e.dataOffset%64 != 0 {
			t.Fatalf("entry %s data offset %d not aligned", e.name, e.dataOffset)
		}
	}
}
