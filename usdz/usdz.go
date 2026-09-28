// Package usdz 提供 USDZ 模型包的校验与规范化能力。
// 输入输出均为内存字节，不落盘。
package usdz

// Reason 表示校验发现的问题原因类别。
type Reason int

const (
	// ReasonCorrupt 包结构损坏（截断、偏移越界、记录矛盾、数据区重叠、长度不符等）。
	ReasonCorrupt Reason = iota
	// ReasonEncrypted 条目被加密。
	ReasonEncrypted
	// ReasonUnsupportedMethod 使用了不支持的压缩方式（非 stored/deflate）。
	ReasonUnsupportedMethod
	// ReasonCompressed 条目使用了 deflate 压缩。
	ReasonCompressed
	// ReasonMisaligned 条目数据起始偏移不是 64 的倍数。
	ReasonMisaligned
	// ReasonFirstNotLayer 第一个内容条目不是 usda/usdc/usd 图层。
	ReasonFirstNotLayer
	// ReasonBadExtension 条目扩展名不在允许列表内。
	ReasonBadExtension
	// ReasonBadPath 条目名非法（绝对路径、含 .. 段、含反斜杠等）。
	ReasonBadPath
	// ReasonDuplicateName 条目名忽略大小写后重名。
	ReasonDuplicateName
	// ReasonCRCMismatch 条目解压内容与记录的 CRC32 不一致。
	ReasonCRCMismatch
	// ReasonTooLarge 输入或规范化结果超过 50 MiB。
	ReasonTooLarge
)

// String 返回原因的中文描述。
func (r Reason) String() string {
	switch r {
	case ReasonCorrupt:
		return "损坏"
	case ReasonEncrypted:
		return "加密"
	case ReasonUnsupportedMethod:
		return "不支持的压缩方式"
	case ReasonCompressed:
		return "已压缩"
	case ReasonMisaligned:
		return "未对齐"
	case ReasonFirstNotLayer:
		return "首条目不是图层"
	case ReasonBadExtension:
		return "扩展名不允许"
	case ReasonBadPath:
		return "路径非法"
	case ReasonDuplicateName:
		return "重名"
	case ReasonCRCMismatch:
		return "校验值不符"
	case ReasonTooLarge:
		return "超限"
	default:
		return "未知"
	}
}

// Issue 描述校验发现的一个问题。整包问题 Entry 为空。
type Issue struct {
	Reason Reason
	Entry  string
}

// MaxSize 是输入与规范化输出的体积上限（50 MiB）。
const MaxSize = 50 << 20

// Validate 校验 data 是否为合规 USDZ 包，返回全部问题。
// 返回空切片表示合规。
func Validate(data []byte) []Issue {
	if len(data) > MaxSize {
		return []Issue{{Reason: ReasonTooLarge}}
	}
	entries, issues := parseZip(data)
	if entries == nil {
		return issues
	}
	return append(issues, validateParsed(data, entries)...)
}

// Normalize 尝试将 data 规范化为合规 USDZ 包。
// 仅当全部问题都属于可修复类别（已压缩、未对齐、目录条目）时返回规范化后的字节；
// 否则返回 nil 与完整问题清单。
func Normalize(data []byte) ([]byte, []Issue) {
	if len(data) > MaxSize {
		return nil, []Issue{{Reason: ReasonTooLarge}}
	}
	entries, issues := parseZip(data)
	if entries != nil {
		issues = append(issues, validateParsed(data, entries)...)
	}
	for _, is := range issues {
		if is.Reason != ReasonCompressed && is.Reason != ReasonMisaligned {
			return nil, issues
		}
	}
	if entries == nil {
		return nil, issues
	}
	out, err := normalizeParsed(entries, data)
	if err == errTooLarge {
		return nil, []Issue{{Reason: ReasonTooLarge}}
	}
	if err != nil {
		return nil, []Issue{{Reason: ReasonCorrupt}}
	}
	return out, nil
}
