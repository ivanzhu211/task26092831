package usdz

import (
	"testing"
)

func TestValidateEmptyZip(t *testing.T) {
	data := buildZip(nil, nil, false)
	// 空包不崩溃；无内容条目，规则上不报错。
	_ = Validate(data)
}

func TestNormalizeNotZip(t *testing.T) {
	out, issues := Normalize([]byte("definitely not a zip file"))
	if out != nil || len(issues) != 1 || issues[0].Reason != ReasonCorrupt {
		t.Fatalf("expected corrupt reject, got %v", issues)
	}
}

func TestValidateManyEntries(t *testing.T) {
	// 条目数较多时（含重名检测）不崩溃。
	var entries []zentry
	entries = append(entries, zentry{name: "scene.usda", content: []byte("#usda")})
	for i := 0; i < 2000; i++ {
		entries = append(entries, zentry{
			name:    "tex/" + string(rune('a'+i%26)) + "/" + itoa(i) + ".png",
			content: []byte("x"),
		})
	}
	data := buildZip(entries, nil, false)
	if issues := Validate(data); len(issues) != 0 {
		t.Fatalf("expected valid, got %v", issues[:1])
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

// FuzzValidate 用随机与变异输入验证不崩溃、不卡住。
func FuzzValidate(f *testing.F) {
	f.Add(buildZip(validEntries(), nil, false))
	f.Add(buildZip(validEntries(), nil, true))
	f.Add([]byte("PK\x05\x06"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4<<20 {
			return // 限制 fuzz 输入规模，语料已覆盖结构变异
		}
		issues := Validate(data)
		// 对可修复输入再验证规范化路径。
		fixable := true
		for _, is := range issues {
			if is.Reason != ReasonCompressed && is.Reason != ReasonMisaligned {
				fixable = false
				break
			}
		}
		if fixable {
			out, _ := Normalize(data)
			if out != nil && len(out) <= MaxSize {
				if got := Validate(out); len(got) != 0 {
					t.Fatalf("normalized output invalid: %v", got)
				}
			}
		}
	})
}
