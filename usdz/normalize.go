package usdz

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"io"
)

// errTooLarge 表示规范化结果超过体积上限。
var errTooLarge = errors.New("normalized output exceeds size limit")

// padExtraID 是用于对齐填充的扩展字段 ID（未分配，解析器应跳过）。
const padExtraID = 0xFFFF

// extractContent 取出条目解压后的内容。
// 解压读取量以 MaxSize+1 为上限，超出说明结果必然超限。
func extractContent(data []byte, e *zipEntry) ([]byte, error) {
	raw := data[e.dataOffset : e.dataOffset+e.compressedSize]
	if e.method == 0 {
		return raw, nil
	}
	if e.size > MaxSize {
		return nil, errTooLarge
	}
	fr := flate.NewReader(bytes.NewReader(raw))
	defer fr.Close()
	out, err := io.ReadAll(io.LimitReader(fr, MaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(out) > MaxSize {
		return nil, errTooLarge
	}
	if uint64(len(out)) != e.size {
		return nil, errors.New("inflated size mismatch")
	}
	return out, nil
}

// normalizeParsed 将已解析条目重写为合规 USDZ 包。
// 去掉目录条目，解压 deflate 条目，按 64 字节对齐数据区；
// 其余条目的顺序、名字、解压后的内容和修改时间保持不变。
// 输出是确定性的：同一输入每次产生逐字节相同的结果。
func normalizeParsed(entries []zipEntry, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	var cd bytes.Buffer
	count := 0

	for i := range entries {
		e := &entries[i]
		if e.isDir {
			continue
		}
		content, err := extractContent(data, e)
		if err != nil {
			return nil, err
		}
		size := uint64(len(content))
		offset := uint64(buf.Len())
		nameLen := len(e.name)

		// 计算对齐填充：扩展字段总长 need（含 4 字节头），
		// 使数据起始偏移为 64 的倍数。
		base := offset + 30 + uint64(nameLen)
		need := (64 - base%64) % 64
		if need > 0 && need < 4 {
			need += 64
		}

		// 本地头。
		var lh [30]byte
		binary.LittleEndian.PutUint32(lh[0:], sigLocal)
		binary.LittleEndian.PutUint16(lh[4:], 20) // version needed
		binary.LittleEndian.PutUint16(lh[6:], 0)  // flags
		binary.LittleEndian.PutUint16(lh[8:], 0)  // method: stored
		binary.LittleEndian.PutUint16(lh[10:], e.modTime)
		binary.LittleEndian.PutUint16(lh[12:], e.modDate)
		binary.LittleEndian.PutUint32(lh[14:], e.crc32)
		binary.LittleEndian.PutUint32(lh[18:], uint32(size))
		binary.LittleEndian.PutUint32(lh[22:], uint32(size))
		binary.LittleEndian.PutUint16(lh[26:], uint16(nameLen))
		binary.LittleEndian.PutUint16(lh[28:], uint16(need))
		buf.Write(lh[:])
		buf.WriteString(e.name)
		if need > 0 {
			var eh [4]byte
			binary.LittleEndian.PutUint16(eh[0:], padExtraID)
			binary.LittleEndian.PutUint16(eh[2:], uint16(need-4))
			buf.Write(eh[:])
			buf.Write(make([]byte, need-4))
		}
		buf.Write(content)

		// 中央目录记录。
		var ch [46]byte
		binary.LittleEndian.PutUint32(ch[0:], sigCentral)
		binary.LittleEndian.PutUint16(ch[4:], 20) // version made by
		binary.LittleEndian.PutUint16(ch[6:], 20) // version needed
		binary.LittleEndian.PutUint16(ch[8:], 0)  // flags
		binary.LittleEndian.PutUint16(ch[10:], 0) // method: stored
		binary.LittleEndian.PutUint16(ch[12:], e.modTime)
		binary.LittleEndian.PutUint16(ch[14:], e.modDate)
		binary.LittleEndian.PutUint32(ch[16:], e.crc32)
		binary.LittleEndian.PutUint32(ch[20:], uint32(size))
		binary.LittleEndian.PutUint32(ch[24:], uint32(size))
		binary.LittleEndian.PutUint16(ch[28:], uint16(nameLen))
		// extra/comment 长度、磁盘号、属性均为 0。
		binary.LittleEndian.PutUint32(ch[42:], uint32(offset))
		cd.Write(ch[:])
		cd.WriteString(e.name)
		count++

		if buf.Len() > MaxSize {
			return nil, errTooLarge
		}
	}

	cdOffset := uint64(buf.Len())
	buf.Write(cd.Bytes())
	cdSize := uint64(buf.Len()) - cdOffset

	// EOCD；条目数超出 16 位时写 ZIP64 EOCD 与定位器。
	z64 := count > 0xFFFF
	if z64 {
		z64off := uint64(buf.Len())
		var z [56]byte
		binary.LittleEndian.PutUint32(z[0:], sigZ64EOCD)
		binary.LittleEndian.PutUint64(z[4:], 44) // record size
		binary.LittleEndian.PutUint16(z[12:], 20)
		binary.LittleEndian.PutUint16(z[14:], 20)
		binary.LittleEndian.PutUint64(z[24:], uint64(count))
		binary.LittleEndian.PutUint64(z[32:], uint64(count))
		binary.LittleEndian.PutUint64(z[40:], cdSize)
		binary.LittleEndian.PutUint64(z[48:], cdOffset)
		buf.Write(z[:])

		var loc [20]byte
		binary.LittleEndian.PutUint32(loc[0:], sigZ64Loc)
		binary.LittleEndian.PutUint64(loc[8:], z64off)
		binary.LittleEndian.PutUint32(loc[16:], 1) // total disks
		buf.Write(loc[:])
	}

	var eo [22]byte
	binary.LittleEndian.PutUint32(eo[0:], sigEOCD)
	if z64 {
		binary.LittleEndian.PutUint16(eo[8:], 0xFFFF)
		binary.LittleEndian.PutUint16(eo[10:], 0xFFFF)
		binary.LittleEndian.PutUint32(eo[12:], 0xFFFFFFFF)
		binary.LittleEndian.PutUint32(eo[16:], 0xFFFFFFFF)
	} else {
		binary.LittleEndian.PutUint16(eo[8:], uint16(count))
		binary.LittleEndian.PutUint16(eo[10:], uint16(count))
		binary.LittleEndian.PutUint32(eo[12:], uint32(cdSize))
		binary.LittleEndian.PutUint32(eo[16:], uint32(cdOffset))
	}
	buf.Write(eo[:])

	if buf.Len() > MaxSize {
		return nil, errTooLarge
	}
	return buf.Bytes(), nil
}
