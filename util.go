package main

import (
	"strings"
	"math"
)

const (
	x86 int8 = iota
	x64
)

func Sub[T any](arr []T, size uint8) []T {
	return arr[:size]
}

func Map[T, F any](arr []T, fn func(T) F) []F {
	result := make([]F, len(arr))

	for i, v := range arr {
		result[i] = fn(v)
	}

	return result
}

func GetString(bytes []byte) string {
	builder := new(strings.Builder)

	for i := 0; bytes[i] != 0; i++ {
		builder.WriteByte(bytes[i])
	}

	return builder.String()
}

func Bytes2uint(bytes []byte) (result uint) {
	for i := 0; i < len(bytes); i++ {
		result += uint(bytes[i]) * uint(math.Pow(0x10, float64(i << 1)))
	}

	return
}

func Uint2bytes(num uint, size int) []byte {
	interim := num
	result  := make([]byte, size)

	for i := 0; i < size; i++ {
		result[i] = byte(interim % 0x100)

		if interim /= 0x100; interim < 0x100 {
			result[i + 1] = byte(interim)
			break
		}
	}

	return result
}

func GetEnclosingSection(rva uint, scnHds []*Header) int {
	lstIdx := len(scnHds) - 1
	lstVS  := scnHds[lstIdx].elems[1].data
	lstVA  := scnHds[lstIdx].elems[2].data
	getVA  := func(h *Header) uint {
		return h.elems[2].data
	}

	for i, v := range scnHds[:lstIdx] {
		if getVA(v) < rva && rva < getVA(scnHds[i + 1]) {
			return i
		}
	}

	switch maxAddr := lstVA + lstVS; {
	case rva < maxAddr: return lstIdx
	default:            return -1
	}
}

func RvaToRawWithScn(rva uint, scnHd *Header) uint {
	return rva + scnHd.elems[4].data - scnHd.elems[2].data
}

type ElemDetails struct {
	size uint8
	addr uint8
	data uint
	name string
	val  string
}

type Header struct {
	offset uint
	size   uint
	elems  []*ElemDetails
}

type PeHeader struct {
	dosHeader      *Header
	fileHeader     *Header
	optionalHeader *Header
	dataDirectory  *Header
	sectionHeaders []*Header
}

func (pe *PeHeader) RvaToRaw(rva uint) uint {
	if scnIdx := GetEnclosingSection(rva, pe.sectionHeaders); scnIdx >= 0 {
		return RvaToRawWithScn(rva, pe.sectionHeaders[scnIdx])
	}
	
	panic("can not know a section including rva")
}

type TblInfo struct {
	ordinal uint16
	rva     uint32
	name    string
}

type ImageImportDescriptor struct {
	Header
	info []*TblInfo
}

type ImportTable struct {
	offset uint
	size   uint
	iids   []*ImageImportDescriptor
}

type ExportTable struct {
	Header
	info []*TblInfo
}