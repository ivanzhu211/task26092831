package usdz

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"hash/crc32"
)

// zentry 描述测试用 ZIP 的一个条目。
type zentry struct {
	name    string
	content []byte // 解压后内容
	method  uint16 // 0=stored, 8=deflate
	flags   uint16 // 附加标志位（如加密位）
	dd      bool   // 流式写出：bit3 + 数据描述符
	noAlign bool   // 不做 64 字节对齐
	crc     uint32 // 覆盖 CRC（hasCRC 时生效）
	hasCRC  bool
	size    *uint64 // 覆盖记录中的解压长度
	csize   *uint64 // 覆盖记录中的压缩长度
	modTime uint16
	modDate uint16
}

// buildZip 构造测试用 ZIP 包。默认对每个条目做 64 字节对齐；
// forceZip64 时即使包很小也写 ZIP64 记录。
func buildZip(entries []zentry, comment []byte, forceZip64 bool) []byte {
	var buf bytes.Buffer
	type rec struct {
		zentry
		offset      uint64
		crc         uint32
		csize, size uint64
		comp        []byte
	}
	var recs []rec

	for _, e := range entries {
		comp := e.content
		if e.method == 8 {
			comp = deflateBytes(e.content)
		}
		crc := crc32.ChecksumIEEE(e.content)
		if e.hasCRC {
			crc = e.crc
		}
		csize, size := uint64(len(comp)), uint64(len(e.content))
		if e.csize != nil {
			csize = *e.csize
		}
		if e.size != nil {
			size = *e.size
		}
		flags := e.flags
		if e.dd {
			flags |= flagDataDescriptor
		}
		offset := uint64(buf.Len())

		var extra []byte
		if !e.noAlign {
			base := offset + 30 + uint64(len(e.name))
			need := (64 - base%64) % 64
			if need > 0 && need < 4 {
				need += 64
			}
			if need > 0 {
				var eh [4]byte
				binary.LittleEndian.PutUint16(eh[0:], padExtraID)
				binary.LittleEndian.PutUint16(eh[2:], uint16(need-4))
				extra = append(eh[:], make([]byte, need-4)...)
			}
		}

		var lh [30]byte
		binary.LittleEndian.PutUint32(lh[0:], sigLocal)
		binary.LittleEndian.PutUint16(lh[4:], 20)
		binary.LittleEndian.PutUint16(lh[6:], flags)
		binary.LittleEndian.PutUint16(lh[8:], e.method)
		binary.LittleEndian.PutUint16(lh[10:], e.modTime)
		binary.LittleEndian.PutUint16(lh[12:], e.modDate)
		lc, ls := csize, size
		if e.dd {
			lc, ls = 0, 0 // 流式写出：本地头大小字段置零
		}
		binary.LittleEndian.PutUint32(lh[14:], crc)
		binary.LittleEndian.PutUint32(lh[18:], uint32(lc))
		binary.LittleEndian.PutUint32(lh[22:], uint32(ls))
		binary.LittleEndian.PutUint16(lh[26:], uint16(len(e.name)))
		binary.LittleEndian.PutUint16(lh[28:], uint16(len(extra)))
		buf.Write(lh[:])
		buf.WriteString(e.name)
		buf.Write(extra)
		buf.Write(comp)
		if e.dd {
			var dd [16]byte
			binary.LittleEndian.PutUint32(dd[0:], 0x08074b50)
			binary.LittleEndian.PutUint32(dd[4:], crc)
			binary.LittleEndian.PutUint32(dd[8:], uint32(csize))
			binary.LittleEndian.PutUint32(dd[12:], uint32(size))
			buf.Write(dd[:])
		}
		recs = append(recs, rec{e, offset, crc, csize, size, comp})
	}

	cdOffset := uint64(buf.Len())
	for _, r := range recs {
		var ch [46]byte
		binary.LittleEndian.PutUint32(ch[0:], sigCentral)
		binary.LittleEndian.PutUint16(ch[4:], 20)
		binary.LittleEndian.PutUint16(ch[6:], 20)
		flags := r.flags
		if r.dd {
			flags |= flagDataDescriptor
		}
		binary.LittleEndian.PutUint16(ch[8:], flags)
		binary.LittleEndian.PutUint16(ch[10:], r.method)
		binary.LittleEndian.PutUint16(ch[12:], r.modTime)
		binary.LittleEndian.PutUint16(ch[14:], r.modDate)
		binary.LittleEndian.PutUint32(ch[16:], r.crc)
		nameLen := uint16(len(r.name))
		binary.LittleEndian.PutUint16(ch[28:], nameLen)
		if forceZip64 {
			// 32 位字段饱和，真实值放进 ZIP64 扩展字段。
			binary.LittleEndian.PutUint32(ch[20:], 0xFFFFFFFF)
			binary.LittleEndian.PutUint32(ch[24:], 0xFFFFFFFF)
			binary.LittleEndian.PutUint32(ch[42:], 0xFFFFFFFF)
			var zx [28]byte
			binary.LittleEndian.PutUint16(zx[0:], extraZip64)
			binary.LittleEndian.PutUint16(zx[2:], 24)
			binary.LittleEndian.PutUint64(zx[4:], r.size)
			binary.LittleEndian.PutUint64(zx[12:], r.csize)
			binary.LittleEndian.PutUint64(zx[20:], r.offset)
			binary.LittleEndian.PutUint16(ch[30:], uint16(len(zx)))
			buf.Write(ch[:])
			buf.WriteString(r.name)
			buf.Write(zx[:])
		} else {
			binary.LittleEndian.PutUint32(ch[20:], uint32(r.csize))
			binary.LittleEndian.PutUint32(ch[24:], uint32(r.size))
			binary.LittleEndian.PutUint32(ch[42:], uint32(r.offset))
			buf.Write(ch[:])
			buf.WriteString(r.name)
		}
	}
	cdSize := uint64(buf.Len()) - cdOffset

	if forceZip64 {
		z64off := uint64(buf.Len())
		var z [56]byte
		binary.LittleEndian.PutUint32(z[0:], sigZ64EOCD)
		binary.LittleEndian.PutUint64(z[4:], 44)
		binary.LittleEndian.PutUint16(z[12:], 20)
		binary.LittleEndian.PutUint16(z[14:], 20)
		binary.LittleEndian.PutUint64(z[24:], uint64(len(recs)))
		binary.LittleEndian.PutUint64(z[32:], uint64(len(recs)))
		binary.LittleEndian.PutUint64(z[40:], cdSize)
		binary.LittleEndian.PutUint64(z[48:], cdOffset)
		buf.Write(z[:])
		var loc [20]byte
		binary.LittleEndian.PutUint32(loc[0:], sigZ64Loc)
		binary.LittleEndian.PutUint64(loc[8:], z64off)
		binary.LittleEndian.PutUint32(loc[16:], 1)
		buf.Write(loc[:])
	}

	var eo [22]byte
	binary.LittleEndian.PutUint32(eo[0:], sigEOCD)
	if forceZip64 {
		binary.LittleEndian.PutUint16(eo[8:], 0xFFFF)
		binary.LittleEndian.PutUint16(eo[10:], 0xFFFF)
		binary.LittleEndian.PutUint32(eo[12:], 0xFFFFFFFF)
		binary.LittleEndian.PutUint32(eo[16:], 0xFFFFFFFF)
	} else {
		binary.LittleEndian.PutUint16(eo[8:], uint16(len(recs)))
		binary.LittleEndian.PutUint16(eo[10:], uint16(len(recs)))
		binary.LittleEndian.PutUint32(eo[12:], uint32(cdSize))
		binary.LittleEndian.PutUint32(eo[16:], uint32(cdOffset))
	}
	binary.LittleEndian.PutUint16(eo[20:], uint16(len(comment)))
	buf.Write(eo[:])
	buf.Write(comment)
	return buf.Bytes()
}

// deflateBytes 用 raw deflate 压缩内容。
func deflateBytes(content []byte) []byte {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write(content)
	w.Close()
	return buf.Bytes()
}

// reasons 返回问题清单中的原因列表。
func reasons(issues []Issue) []Reason {
	var out []Reason
	for _, is := range issues {
		out = append(out, is.Reason)
	}
	return out
}

// hasReason 报告问题清单是否包含指定原因。
func hasReason(issues []Issue, r Reason) bool {
	for _, is := range issues {
		if is.Reason == r {
			return true
		}
	}
	return false
}

// crc32Of 计算 IEEE CRC32（测试辅助）。
func crc32Of(b []byte) uint32 {
	return crc32.ChecksumIEEE(b)
}
