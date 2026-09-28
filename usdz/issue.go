package usdz

// Reason 是不合规原因分类。
type Reason string

const (
	ReasonCorrupt                 Reason = "损坏"
	ReasonEncrypted               Reason = "加密"
	ReasonUnsupportedCompression  Reason = "不支持的压缩方式"
	ReasonCompressed              Reason = "已压缩"
	ReasonMisaligned              Reason = "未对齐"
	ReasonFirstNotLayer           Reason = "首条目不是图层"
	ReasonBadExtension            Reason = "扩展名不允许"
	ReasonIllegalPath             Reason = "路径非法"
	ReasonDuplicate               Reason = "重名"
	ReasonCRCMismatch             Reason = "校验值不符"
	ReasonTooLarge                Reason = "超限"
)

// Issue 描述一个合规性问题。整包问题的 Entry 为空。
type Issue struct {
	Reason Reason
	Entry  string
}

func (i Issue) String() string {
	return ""
}
