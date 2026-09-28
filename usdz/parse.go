package usdz

// rawEntry 是中央目录中的一个条目及其本地头信息。
type rawEntry struct {
	name string
	isDir bool

	method           uint16
	flags            uint16
	crc              uint32
	compressedSize   uint64
	uncompressedSize uint64
	modTime          uint16
	modDate         uint16
	localOffset      uint64

	// 本地头解析结果
	localParsed           bool
	dataOffset            uint64
	localName             string
	localMethod           uint16
	localCompressedSize   uint64
	localUncompressedSize uint64
	localHasZip64Sizes    bool
}

// contentEntry 是规范化后要写出的一个内容条目。
type contentEntry struct {
	name    string
	data    []byte
	modTime uint16
	modDate uint16
}

type parsedZip struct {
	entries []*rawEntry
}

// parseZip 尽力解析一个不可信的 ZIP 包，返回条目与结构性问题。
func parseZip(data []byte) (*parsedZip, []Issue) {
	return nil, nil
}
