package usdz

import (
	"encoding/binary"
)

const (
	sigLocal   = 0x04034b50
	sigCentral = 0x02014b50
	sigEOCD    = 0x06054b50
	sigZ64EOCD = 0x06064b50
	sigZ64Loc  = 0x07064b50

	extraZip64 = 0x0001

	flagEncrypted      = 1 << 0
	flagDataDescriptor = 1 << 3

	maxCommentLen = 65535
)

// zipEntry 是从 ZIP 中央目录解析出的一个条目。
type zipEntry struct {
	name           string
	method         uint16
	flags          uint16
	crc32          uint32
	compressedSize uint64
	size           uint64
	localOffset    uint64
	dataOffset     uint64 // 本地头之后的数据起始偏移
	modTime        uint16
	modDate        uint16
	isDir          bool
	dataOK         bool // 数据区边界合法，可安全读取
}

// parseZip 解析 ZIP 包，返回按中央目录顺序排列的条目。
// 解析过程中发现的结构性问题以 ReasonCorrupt 问题返回；
// 若包整体无法解析，entries 为 nil 且 issues 只含一个整包级损坏问题。
func parseZip(data []byte) (entries []zipEntry, issues []Issue) {
	cdOffset, cdSize, cdCount, ok := findDirectory(data)
	if !ok {
		return nil, []Issue{{Reason: ReasonCorrupt}}
	}
	if cdCount > 0 && cdSize/46 < cdCount {
		return nil, []Issue{{Reason: ReasonCorrupt}}
	}

	pos := cdOffset
	end := cdOffset + cdSize
	for i := uint64(0); i < cdCount; i++ {
		if pos+46 > end {
			return nil, []Issue{{Reason: ReasonCorrupt}}
		}
		h := data[pos : pos+46]
		if binary.LittleEndian.Uint32(h[0:]) != sigCentral {
			return nil, []Issue{{Reason: ReasonCorrupt}}
		}
		e := zipEntry{
			flags:          binary.LittleEndian.Uint16(h[8:]),
			method:         binary.LittleEndian.Uint16(h[10:]),
			modTime:        binary.LittleEndian.Uint16(h[12:]),
			modDate:        binary.LittleEndian.Uint16(h[14:]),
			crc32:          binary.LittleEndian.Uint32(h[16:]),
			compressedSize: uint64(binary.LittleEndian.Uint32(h[20:])),
			size:           uint64(binary.LittleEndian.Uint32(h[24:])),
			localOffset:    uint64(binary.LittleEndian.Uint32(h[42:])),
		}
		nameLen := int(binary.LittleEndian.Uint16(h[28:]))
		extraLen := int(binary.LittleEndian.Uint16(h[30:]))
		commentLen := int(binary.LittleEndian.Uint16(h[32:]))
		diskStart := binary.LittleEndian.Uint16(h[34:])
		recLen := uint64(46 + nameLen + extraLen + commentLen)
		if pos+recLen > end {
			return nil, []Issue{{Reason: ReasonCorrupt}}
		}
		if diskStart != 0 {
			return nil, []Issue{{Reason: ReasonCorrupt}}
		}
		e.name = string(data[pos+46 : pos+46+uint64(nameLen)])
		extra := data[pos+46+uint64(nameLen) : pos+46+uint64(nameLen+extraLen)]

		// ZIP64 扩展字段：仅当对应 32 位字段饱和时出现，顺序为 size/csize/offset。
		if e.size == 0xFFFFFFFF || e.compressedSize == 0xFFFFFFFF || e.localOffset == 0xFFFFFFFF {
			if !readZip64Extra(extra, &e) {
				return nil, []Issue{{Reason: ReasonCorrupt}}
			}
		}
		e.isDir = len(e.name) > 0 && e.name[len(e.name)-1] == '/'
		entries = append(entries, e)
		pos += recLen
	}

	// 本地头交叉校验与数据区定位。
	for i := range entries {
		if msg := checkLocalHeader(data, &entries[i]); msg != "" {
			issues = append(issues, Issue{Reason: ReasonCorrupt, Entry: entries[i].name})
			continue
		}
		entries[i].dataOK = true
	}

	// 数据区重叠检查（仅内容条目）。
	checkOverlap(entries, &issues)

	return entries, issues
}

// findDirectory 定位 EOCD 并返回中央目录的偏移、大小与条目数。
// 从文件尾向前搜索签名，并要求注释长度恰好到文件尾，
// 因此注释中含有的 ZIP 签名字节不会造成误判。
func findDirectory(data []byte) (cdOffset, cdSize, cdCount uint64, ok bool) {
	n := len(data)
	if n < 22 {
		return 0, 0, 0, false
	}
	lower := n - 22 - maxCommentLen
	if lower < 0 {
		lower = 0
	}
	for p := n - 22; p >= lower; p-- {
		if binary.LittleEndian.Uint32(data[p:]) != sigEOCD {
			continue
		}
		commentLen := int(binary.LittleEndian.Uint16(data[p+20:]))
		if p+22+commentLen != n {
			continue
		}
		// 多分卷包不支持。
		if binary.LittleEndian.Uint16(data[p+4:]) != 0 ||
			binary.LittleEndian.Uint16(data[p+6:]) != 0 {
			return 0, 0, 0, false
		}
		cdCount = uint64(binary.LittleEndian.Uint16(data[p+10:]))
		cdSize = uint64(binary.LittleEndian.Uint32(data[p+12:]))
		cdOffset = uint64(binary.LittleEndian.Uint32(data[p+16:]))

		if cdCount == 0xFFFF || cdSize == 0xFFFFFFFF || cdOffset == 0xFFFFFFFF {
			// ZIP64：定位器必须紧跟 EOCD。
			if p < 20 || binary.LittleEndian.Uint32(data[p-20:]) != sigZ64Loc {
				return 0, 0, 0, false
			}
			z64off := binary.LittleEndian.Uint64(data[p-20+8:])
			if z64off > uint64(n) || uint64(n)-z64off < 56 ||
				binary.LittleEndian.Uint32(data[z64off:]) != sigZ64EOCD {
				return 0, 0, 0, false
			}
			cdCount = binary.LittleEndian.Uint64(data[z64off+32:])
			cdSize = binary.LittleEndian.Uint64(data[z64off+40:])
			cdOffset = binary.LittleEndian.Uint64(data[z64off+48:])
		}
		if cdSize > uint64(n) || cdOffset > uint64(n)-cdSize {
			return 0, 0, 0, false
		}
		if cdOffset+cdSize > uint64(p) {
			return 0, 0, 0, false
		}
		return cdOffset, cdSize, cdCount, true
	}
	return 0, 0, 0, false
}

// readZip64Extra 从扩展字段中读取 ZIP64 数值，按饱和字段顺序填充。
func readZip64Extra(extra []byte, e *zipEntry) bool {
	for len(extra) >= 4 {
		id := binary.LittleEndian.Uint16(extra[0:])
		sz := int(binary.LittleEndian.Uint16(extra[2:]))
		if 4+sz > len(extra) {
			return false
		}
		body := extra[4 : 4+sz]
		if id == extraZip64 {
			for len(body) >= 8 {
				switch {
				case e.size == 0xFFFFFFFF:
					e.size = binary.LittleEndian.Uint64(body)
				case e.compressedSize == 0xFFFFFFFF:
					e.compressedSize = binary.LittleEndian.Uint64(body)
				case e.localOffset == 0xFFFFFFFF:
					e.localOffset = binary.LittleEndian.Uint64(body)
				default:
					return true
				}
				body = body[8:]
			}
			return e.size != 0xFFFFFFFF && e.compressedSize != 0xFFFFFFFF &&
				e.localOffset != 0xFFFFFFFF
		}
		extra = extra[4+sz:]
	}
	return false
}

// checkLocalHeader 校验本地头与中央目录记录一致，并计算数据区偏移。
// 返回空串表示一致且数据区边界合法。
func checkLocalHeader(data []byte, e *zipEntry) string {
	n := uint64(len(data))
	if e.localOffset > n || n-e.localOffset < 30 {
		return "local header out of bounds"
	}
	h := data[e.localOffset : e.localOffset+30]
	if binary.LittleEndian.Uint32(h[0:]) != sigLocal {
		return "bad local signature"
	}
	localFlags := binary.LittleEndian.Uint16(h[6:])
	localMethod := binary.LittleEndian.Uint16(h[8:])
	nameLen := uint64(binary.LittleEndian.Uint16(h[26:]))
	extraLen := uint64(binary.LittleEndian.Uint16(h[28:]))
	if localMethod != e.method {
		return "method mismatch"
	}
	dataStart := e.localOffset + 30
	if nameLen > n-dataStart || dataStart+nameLen+extraLen > n {
		return "local header truncated"
	}
	if string(data[dataStart:dataStart+nameLen]) != e.name {
		return "name mismatch"
	}
	if localFlags&flagDataDescriptor == 0 {
		// 非流式写出：本地头的大小记录必须与中央目录一致。
		localCSize := uint64(binary.LittleEndian.Uint32(h[18:]))
		localSize := uint64(binary.LittleEndian.Uint32(h[22:]))
		if localCSize != e.compressedSize || localSize != e.size {
			return "size mismatch"
		}
	}
	e.dataOffset = dataStart + nameLen + extraLen
	if e.compressedSize > n-e.dataOffset {
		return "data out of bounds"
	}
	// stored 条目的压缩前后长度必须相等。
	if e.method == 0 && e.compressedSize != e.size {
		return "stored size mismatch"
	}
	return ""
}

// checkOverlap 检查内容条目的数据区是否两两重叠。
func checkOverlap(entries []zipEntry, issues *[]Issue) {
	type region struct {
		start, end uint64
		idx        int
	}
	var regions []region
	for i := range entries {
		e := &entries[i]
		if e.isDir || !e.dataOK {
			continue
		}
		regions = append(regions, region{e.dataOffset, e.dataOffset + e.compressedSize, i})
	}
	// 按起始偏移排序（插入排序，条目数通常不大）。
	for i := 1; i < len(regions); i++ {
		for j := i; j > 0 && regions[j].start < regions[j-1].start; j-- {
			regions[j], regions[j-1] = regions[j-1], regions[j]
		}
	}
	reported := make(map[int]bool)
	for i := 1; i < len(regions); i++ {
		if regions[i].start < regions[i-1].end {
			idx := regions[i].idx
			if !reported[idx] {
				reported[idx] = true
				*issues = append(*issues, Issue{Reason: ReasonCorrupt, Entry: entries[idx].name})
			}
		}
	}
}
