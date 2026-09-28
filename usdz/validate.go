package usdz

import (
	"bytes"
	"compress/flate"
	"hash/crc32"
	"io"
	"strings"
)

// maxDeclaredSize 是单个条目声明解压长度的合理上限。
// 超过此值视为长度字段离谱，按损坏处理，避免解压暴涨耗尽资源。
const maxDeclaredSize = 256 << 20

// allowedExts 是允许的条目扩展名（小写）。
var allowedExts = map[string]bool{
	"usda": true, "usdc": true, "usd": true,
	"png": true, "jpg": true, "jpeg": true,
	"m4a": true, "mp3": true, "wav": true,
}

// layerExts 是首条目允许的图层扩展名（小写）。
var layerExts = map[string]bool{
	"usda": true, "usdc": true, "usd": true,
}

// validateParsed 对已解析的条目执行全部业务规则校验。
func validateParsed(data []byte, entries []zipEntry) []Issue {
	var issues []Issue

	seen := make(map[string]string) // 小写名 -> 首次出现的原名
	firstContent := true

	for i := range entries {
		e := &entries[i]
		if e.isDir {
			continue
		}

		// 首条目必须是图层。
		if firstContent {
			firstContent = false
			if !layerExts[extOf(e.name)] {
				issues = append(issues, Issue{Reason: ReasonFirstNotLayer, Entry: e.name})
			}
		}

		// 路径合法性。
		if !validPath(e.name) {
			issues = append(issues, Issue{Reason: ReasonBadPath, Entry: e.name})
		}

		// 重名（忽略大小写）。
		lower := strings.ToLower(e.name)
		if _, dup := seen[lower]; dup {
			issues = append(issues, Issue{Reason: ReasonDuplicateName, Entry: e.name})
		} else {
			seen[lower] = e.name
		}

		// 扩展名。
		if !allowedExts[extOf(e.name)] {
			issues = append(issues, Issue{Reason: ReasonBadExtension, Entry: e.name})
		}

		// 加密。
		if e.flags&flagEncrypted != 0 {
			issues = append(issues, Issue{Reason: ReasonEncrypted, Entry: e.name})
		}

		// 压缩方式。
		switch e.method {
		case 0:
			// stored，合规。
		case 8:
			issues = append(issues, Issue{Reason: ReasonCompressed, Entry: e.name})
		default:
			issues = append(issues, Issue{Reason: ReasonUnsupportedMethod, Entry: e.name})
		}

		// 对齐。
		if e.dataOK && e.dataOffset%64 != 0 {
			issues = append(issues, Issue{Reason: ReasonMisaligned, Entry: e.name})
		}

		// 内容校验：长度与 CRC32。
		if e.dataOK && (e.method == 0 || e.method == 8) && e.flags&flagEncrypted == 0 {
			lengthBad, crcBad := checkContent(data, e)
			if lengthBad {
				issues = append(issues, Issue{Reason: ReasonCorrupt, Entry: e.name})
			} else if crcBad {
				issues = append(issues, Issue{Reason: ReasonCRCMismatch, Entry: e.name})
			}
		}
	}

	return issues
}

// extOf 返回条目名的小写扩展名（不含点），无扩展名返回空串。
func extOf(name string) string {
	base := name
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	dot := strings.LastIndexByte(base, '.')
	if dot < 0 {
		return ""
	}
	return strings.ToLower(base[dot+1:])
}

// validPath 检查条目名是否合法：非空、非绝对路径、无 .. 段、
// 无反斜杠、无空路径段。
func validPath(name string) bool {
	if name == "" || name[0] == '/' {
		return false
	}
	if strings.ContainsRune(name, '\\') {
		return false
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "" || seg == ".." {
			return false
		}
	}
	return true
}

// checkContent 读取条目解压后的内容，核验长度与 CRC32。
// 流式计算，不缓存内容；解压读取量以声明长度+1 为上限。
func checkContent(data []byte, e *zipEntry) (lengthBad, crcBad bool) {
	if e.size > maxDeclaredSize {
		return true, false
	}
	raw := data[e.dataOffset : e.dataOffset+e.compressedSize]
	var r io.Reader
	if e.method == 0 {
		r = bytes.NewReader(raw)
	} else {
		fr := flate.NewReader(bytes.NewReader(raw))
		defer fr.Close()
		r = fr
	}
	// 最多读取 size+1 字节，防止解压暴涨。
	lr := io.LimitReader(r, int64(e.size)+1)
	h := crc32.NewIEEE()
	n, err := io.Copy(h, lr)
	if err != nil {
		return true, false
	}
	if uint64(n) != e.size {
		return true, false
	}
	if h.Sum32() != e.crc32 {
		return false, true
	}
	return false, false
}
