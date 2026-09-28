package usdz

import (
	"encoding/binary"
	"testing"
)

// validEntries 返回一组合规条目，供各用例在此基础上变异。
func validEntries() []zentry {
	return []zentry{
		{name: "scene.usda", content: []byte("#usda 1.0\n"), modTime: 100, modDate: 200},
		{name: "tex/diffuse.png", content: []byte("fake-png-bytes"), modTime: 101, modDate: 201},
		{name: "audio/voice.WAV", content: []byte("fake-wav"), modTime: 102, modDate: 202},
	}
}

func TestValidateValidPackage(t *testing.T) {
	data := buildZip(validEntries(), nil, false)
	if issues := Validate(data); len(issues) != 0 {
		t.Fatalf("expected no issues, got %v", issues)
	}
}

func TestValidateValidWithDirs(t *testing.T) {
	entries := append([]zentry{{name: "tex/", content: nil}}, validEntries()...)
	data := buildZip(entries, nil, false)
	if issues := Validate(data); len(issues) != 0 {
		t.Fatalf("directory entries should be ignored, got %v", issues)
	}
}

func TestValidateNotZip(t *testing.T) {
	for _, data := range [][]byte{nil, {}, []byte("hello world, not a zip at all")} {
		issues := Validate(data)
		if len(issues) != 1 || issues[0].Reason != ReasonCorrupt {
			t.Fatalf("expected single corrupt issue, got %v", issues)
		}
	}
}

func TestValidateTruncated(t *testing.T) {
	data := buildZip(validEntries(), nil, false)
	issues := Validate(data[:len(data)-10]) // 截掉 EOCD 尾部
	if len(issues) != 1 || issues[0].Reason != ReasonCorrupt {
		t.Fatalf("expected corrupt, got %v", issues)
	}
}

func TestValidateOffsetOutOfBounds(t *testing.T) {
	data := buildZip(validEntries(), nil, false)
	// 把 EOCD 中的中央目录偏移改到文件外。
	n := len(data)
	binary.LittleEndian.PutUint32(data[n-6:], 0x7FFFFFFF)
	issues := Validate(data)
	if len(issues) != 1 || issues[0].Reason != ReasonCorrupt {
		t.Fatalf("expected corrupt, got %v", issues)
	}
}

func TestValidateCompressed(t *testing.T) {
	entries := validEntries()
	entries[1].method = 8
	data := buildZip(entries, nil, false)
	issues := Validate(data)
	if len(issues) != 1 || issues[0].Reason != ReasonCompressed || issues[0].Entry != "tex/diffuse.png" {
		t.Fatalf("expected compressed issue, got %v", issues)
	}
}

func TestValidateMisaligned(t *testing.T) {
	entries := validEntries()
	entries[1].noAlign = true
	data := buildZip(entries, nil, false)
	issues := Validate(data)
	if len(issues) != 1 || issues[0].Reason != ReasonMisaligned || issues[0].Entry != "tex/diffuse.png" {
		t.Fatalf("expected misaligned issue, got %v", issues)
	}
}

func TestValidateEncrypted(t *testing.T) {
	entries := validEntries()
	entries[0].flags = flagEncrypted
	data := buildZip(entries, nil, false)
	issues := Validate(data)
	if len(issues) != 1 || issues[0].Reason != ReasonEncrypted || issues[0].Entry != "scene.usda" {
		t.Fatalf("expected encrypted issue, got %v", issues)
	}
}

func TestValidateUnsupportedMethod(t *testing.T) {
	entries := validEntries()
	entries[1].method = 12 // bzip2
	data := buildZip(entries, nil, false)
	issues := Validate(data)
	if len(issues) != 1 || issues[0].Reason != ReasonUnsupportedMethod {
		t.Fatalf("expected unsupported method, got %v", issues)
	}
}

func TestValidateFirstNotLayer(t *testing.T) {
	entries := []zentry{
		{name: "tex/diffuse.png", content: []byte("png")},
		{name: "scene.usda", content: []byte("#usda 1.0\n")},
	}
	data := buildZip(entries, nil, false)
	issues := Validate(data)
	if len(issues) != 1 || issues[0].Reason != ReasonFirstNotLayer || issues[0].Entry != "tex/diffuse.png" {
		t.Fatalf("expected first-not-layer, got %v", issues)
	}
}

func TestValidateBadExtension(t *testing.T) {
	entries := append(validEntries(),
		zentry{name: "model.obj", content: []byte("x")},
		zentry{name: "noext", content: []byte("y")},
	)
	data := buildZip(entries, nil, false)
	issues := Validate(data)
	if len(issues) != 2 || !hasReason(issues, ReasonBadExtension) {
		t.Fatalf("expected 2 bad-extension issues, got %v", issues)
	}
	for _, is := range issues {
		if is.Reason != ReasonBadExtension {
			t.Fatalf("unexpected issue %v", is)
		}
	}
}

func TestValidateBadPath(t *testing.T) {
	cases := []string{"/abs.usd", "a/../b.usd", "a\\b.usd", "a//b.usd", "..usd/../x.usd"}
	for _, name := range cases {
		entries := append([]zentry{{name: name, content: []byte("z")}}, validEntries()[1:]...)
		data := buildZip(entries, nil, false)
		issues := Validate(data)
		if !hasReason(issues, ReasonBadPath) {
			t.Fatalf("name %q: expected bad-path, got %v", name, issues)
		}
	}
}

func TestValidateDuplicateName(t *testing.T) {
	entries := append(validEntries(), zentry{name: "TEX/DIFFUSE.PNG", content: []byte("other")})
	data := buildZip(entries, nil, false)
	issues := Validate(data)
	if len(issues) != 1 || issues[0].Reason != ReasonDuplicateName || issues[0].Entry != "TEX/DIFFUSE.PNG" {
		t.Fatalf("expected duplicate-name, got %v", issues)
	}
}

func TestValidateCRCMismatch(t *testing.T) {
	entries := validEntries()
	entries[1].hasCRC = true
	entries[1].crc = 0xDEADBEEF
	data := buildZip(entries, nil, false)
	issues := Validate(data)
	if len(issues) != 1 || issues[0].Reason != ReasonCRCMismatch || issues[0].Entry != "tex/diffuse.png" {
		t.Fatalf("expected crc-mismatch, got %v", issues)
	}
}

func TestValidateLengthMismatchDeflate(t *testing.T) {
	// 声明解压长度与实际不符，按损坏处理。
	bad := uint64(9999)
	entries := validEntries()
	entries[1].method = 8
	entries[1].size = &bad
	data := buildZip(entries, nil, false)
	issues := Validate(data)
	if len(issues) == 0 || !hasReason(issues, ReasonCorrupt) {
		t.Fatalf("expected corrupt, got %v", issues)
	}
	if !hasReason(issues, ReasonCompressed) {
		t.Fatalf("expected compressed too, got %v", issues)
	}
}

func TestValidateStoredSizeMismatch(t *testing.T) {
	// stored 条目压缩前后长度记录不一致，按损坏处理。
	bad := uint64(9999)
	entries := validEntries()
	entries[1].csize = &bad
	data := buildZip(entries, nil, false)
	issues := Validate(data)
	if !hasReason(issues, ReasonCorrupt) {
		t.Fatalf("expected corrupt, got %v", issues)
	}
}

func TestValidateLocalCentralMismatch(t *testing.T) {
	// 中央目录与本地头记录矛盾：篡改中央目录里的方法字段。
	data := buildZip(validEntries(), nil, false)
	entries, _ := parseZip(data)
	if entries == nil {
		t.Fatal("parse failed")
	}
	cdOff := findCDOffset(t, data)
	// 第一个中央目录记录的 method 字段在偏移 10。
	binary.LittleEndian.PutUint16(data[cdOff+10:], 8)
	issues := Validate(data)
	if !hasReason(issues, ReasonCorrupt) {
		t.Fatalf("expected corrupt, got %v", issues)
	}
}

func TestValidateLocalNameMismatch(t *testing.T) {
	data := buildZip(validEntries(), nil, false)
	cdOff := findCDOffset(t, data)
	// 篡改中央目录里第一条目的名字首字节（保持长度）。
	nameOff := cdOff + 46
	data[nameOff] = 'X'
	issues := Validate(data)
	if !hasReason(issues, ReasonCorrupt) {
		t.Fatalf("expected corrupt, got %v", issues)
	}
}

func TestValidateOverlappingData(t *testing.T) {
	// 手工构造：条目2的本地头落在条目1的数据区内。
	var buf []byte
	name1, name2 := "a.usd", "b.png"
	content1 := make([]byte, 200)
	for i := range content1 {
		content1[i] = 'A'
	}
	// 条目1本地头（无扩展字段，数据偏移 30+5=35）。
	lh := make([]byte, 30)
	binary.LittleEndian.PutUint32(lh[0:], sigLocal)
	binary.LittleEndian.PutUint16(lh[4:], 20)
	binary.LittleEndian.PutUint16(lh[8:], 0)
	crc1 := crc32Of(content1)
	binary.LittleEndian.PutUint32(lh[14:], crc1)
	binary.LittleEndian.PutUint32(lh[18:], 200)
	binary.LittleEndian.PutUint32(lh[22:], 200)
	binary.LittleEndian.PutUint16(lh[26:], uint16(len(name1)))
	buf = append(buf, lh...)
	buf = append(buf, name1...)
	dataStart1 := uint64(len(buf))
	buf = append(buf, content1...)
	// 条目2本地头放在偏移 100（条目1数据区 [35,235) 内）。
	off2 := uint64(100)
	content2 := []byte("pngdata!!")
	lh2 := make([]byte, 30)
	binary.LittleEndian.PutUint32(lh2[0:], sigLocal)
	binary.LittleEndian.PutUint16(lh2[4:], 20)
	binary.LittleEndian.PutUint16(lh2[8:], 0)
	binary.LittleEndian.PutUint32(lh2[14:], crc32Of(content2))
	binary.LittleEndian.PutUint32(lh2[18:], uint32(len(content2)))
	binary.LittleEndian.PutUint32(lh2[22:], uint32(len(content2)))
	binary.LittleEndian.PutUint16(lh2[26:], uint16(len(name2)))
	copy(buf[off2:], lh2)
	copy(buf[off2+30:], name2)
	copy(buf[off2+30+uint64(len(name2)):], content2)
	// 中央目录。
	cdOff := uint64(len(buf))
	writeCD := func(name string, crc uint32, size, off uint64) {
		ch := make([]byte, 46)
		binary.LittleEndian.PutUint32(ch[0:], sigCentral)
		binary.LittleEndian.PutUint16(ch[4:], 20)
		binary.LittleEndian.PutUint16(ch[6:], 20)
		binary.LittleEndian.PutUint32(ch[16:], crc)
		binary.LittleEndian.PutUint32(ch[20:], uint32(size))
		binary.LittleEndian.PutUint32(ch[24:], uint32(size))
		binary.LittleEndian.PutUint16(ch[28:], uint16(len(name)))
		binary.LittleEndian.PutUint32(ch[42:], uint32(off))
		buf = append(buf, ch...)
		buf = append(buf, name...)
	}
	writeCD(name1, crc1, 200, 0)
	writeCD(name2, crc32Of(content2), uint64(len(content2)), off2)
	cdSize := uint64(len(buf)) - cdOff
	eo := make([]byte, 22)
	binary.LittleEndian.PutUint32(eo[0:], sigEOCD)
	binary.LittleEndian.PutUint16(eo[8:], 2)
	binary.LittleEndian.PutUint16(eo[10:], 2)
	binary.LittleEndian.PutUint32(eo[12:], uint32(cdSize))
	binary.LittleEndian.PutUint32(eo[16:], uint32(cdOff))
	buf = append(buf, eo...)

	issues := Validate(buf)
	if !hasReason(issues, ReasonCorrupt) {
		t.Fatalf("expected corrupt (overlap), got %v", issues)
	}
	_ = dataStart1
}

func TestValidateZip64SmallPackage(t *testing.T) {
	data := buildZip(validEntries(), nil, true)
	if issues := Validate(data); len(issues) != 0 {
		t.Fatalf("zip64 small package should be valid, got %v", issues)
	}
}

func TestValidateStreamingDataDescriptor(t *testing.T) {
	entries := validEntries()
	entries[0].dd = true
	entries[2].dd = true
	data := buildZip(entries, nil, false)
	if issues := Validate(data); len(issues) != 0 {
		t.Fatalf("streaming package should be valid, got %v", issues)
	}
}

func TestValidateCommentWithSignatureBytes(t *testing.T) {
	comment := []byte("note PK\x05\x06 and PK\x03\x04 and PK\x01\x02 inside comment")
	data := buildZip(validEntries(), comment, false)
	if issues := Validate(data); len(issues) != 0 {
		t.Fatalf("comment with signature bytes should be valid, got %v", issues)
	}
}

func TestValidateTooLargeInput(t *testing.T) {
	entries := []zentry{
		{name: "scene.usda", content: []byte("#usda 1.0\n")},
		{name: "big.png", content: make([]byte, MaxSize)},
	}
	data := buildZip(entries, nil, false)
	if len(data) <= MaxSize {
		t.Fatal("test setup: package should exceed limit")
	}
	issues := Validate(data)
	if len(issues) != 1 || issues[0].Reason != ReasonTooLarge {
		t.Fatalf("expected too-large, got %v", issues)
	}
}

func TestValidateHighCompressionRatio(t *testing.T) {
	// 高压缩比包：40 MiB 零字节压到很小，校验不能卡住或崩溃。
	entries := []zentry{
		{name: "scene.usda", content: []byte("#usda 1.0\n")},
		{name: "big.wav", content: make([]byte, 40<<20), method: 8},
	}
	data := buildZip(entries, nil, false)
	issues := Validate(data)
	if len(issues) != 1 || issues[0].Reason != ReasonCompressed {
		t.Fatalf("expected only compressed issue, got %v", issues)
	}
}

func TestValidateAbsurdDeclaredSize(t *testing.T) {
	// 声明解压长度离谱（超过合理上限），按损坏处理且不做巨额解压。
	huge := uint64(64 << 30)
	entries := validEntries()
	entries[1].method = 8
	entries[1].size = &huge
	data := buildZip(entries, nil, false)
	issues := Validate(data)
	if !hasReason(issues, ReasonCorrupt) {
		t.Fatalf("expected corrupt, got %v", issues)
	}
}

// findCDOffset 从 EOCD 读出中央目录偏移（测试辅助）。
func findCDOffset(t *testing.T, data []byte) uint64 {
	t.Helper()
	n := len(data)
	for p := n - 22; p >= 0; p-- {
		if binary.LittleEndian.Uint32(data[p:]) == sigEOCD {
			return uint64(binary.LittleEndian.Uint32(data[p+16:]))
		}
	}
	t.Fatal("no EOCD")
	return 0
}
