package main

import (
	"strings"
	"math"
	"time"
)

type nmSzPair struct {
	nm string
	sz uint8
}

var (
	dosHdNmSz = [...]nmSzPair{
		{"e_magic",    2}, {"e_cblp",     2}, {"e_cp",     2}, {"e_crlc",  2}, {"e_cparhdr", 2},
		{"e_minalloc", 2}, {"e_maxalloc", 2}, {"e_ss",     2}, {"e_sp",    2}, {"e_csum",    2},
		{"e_ip",       2}, {"e_cs",       2}, {"e_lfarlc", 2}, {"e_ovno",  2}, {"e_res",     2},
		{"e_res",      2}, {"e_res",      2}, {"e_res",    2}, {"e_oemid", 2}, {"e_oeminfo", 2},
		{"e_res2",     2}, {"e_res2",     2}, {"e_res2",   2}, {"e_res2",  2}, {"e_res2",    2},
		{"e_res2",     2}, {"e_res2",     2}, {"e_res2",   2}, {"e_res2",  2}, {"e_res2",    2},
		{"e_lfanew",   4},
	}

	flHdNmSz = [...]nmSzPair{
		{"Machine",              2}, {"NumberOfSections", 2}, {"TimeDataStamp",        4}, 
		{"PointerToSymbolTable", 4}, {"NumberOfSymbols",  4}, {"SizeOfOptionalHeader", 2}, 
		{"Characteristics",      2},
	}

	opHd32NmSz = [...]nmSzPair{
		{"Magic",                       2}, {"MajorLinkerVersion",          1}, {"MinorLinkerVersion",      1},
		{"SizeOfCode",                  4}, {"SizeOfInitializedData",       4}, {"SizeOfUninitializedData", 4},
		{"AddressOfEntryPoint",         4}, {"BaseOfCode",                  4}, {"BaseOfData",              4},
		{"ImageBase",                   4}, {"SectionAlignment",            4}, {"FileAlignment",           4},
		{"MajorOperatingSystemVersion", 2}, {"MinorOperatingSystemVersion", 2}, {"MajorImageVersion",       2},
		{"MinorImageVersion",           2}, {"MajorSubsystemVersion",       2}, {"MinorSubsystemVersion",   2},
		{"Win32VersionValue",           4}, {"SizeOfImage",                 4}, {"SizeOfHeaders",           4},
		{"CheckSum",                    4}, {"Subsystem",                   2}, {"DllCharacteristics",      2},
		{"SizeOfStackReserve",          4}, {"SizeOfStackCommit",           4}, {"SizeOfHeapReserve",       4},
		{"SizeOfHeapCommit",            4}, {"LoaderFlags",                 4}, {"NumberOfRvaAndSizes",     4},
	}

	opHd64NmSz = [...]nmSzPair{
		{"Magic",                       2}, {"MajorLinkerVersion",    1}, {"MinorLinkerVersion",          1},
		{"SizeOfCode",                  4}, {"SizeOfInitializedData", 4}, {"SizeOfUninitializedData",     4},
		{"AddressOfEntryPoint",         4}, {"BaseOfCode",            4}, {"ImageBase",                   8},
		{"SectionAlignment",            4}, {"FileAlignment",         4}, {"MajorOperatingSystemVersion", 4},
		{"MinorOperatingSystemVersion", 2}, {"MajorImageVersion",     2}, {"MinorImageVersion",           2},
		{"MajorSubsystemVersion",       2}, {"MinorSubsystemVersion", 2}, {"Win32VersionValue",           4},
		{"SizeOfImage",                 4}, {"SizeOfHeaders",         4}, {"CheckSum",                    4},
		{"Subsystem",                   2}, {"DllCharacteristics",    2}, {"SizeOfStackReserve",          8},
		{"SizeOfStackCommit",           8}, {"SizeOfHeapReserve",     8}, {"SizeOfHeapCommit",            8},
		{"LoaderFlags",                 4}, {"NumberOfRvaAndSizes",   4},
	}

	dataDirNmSz = [...]nmSzPair{
		{"ExportTable RVA",           4}, {"ExportTable Size",           4},
		{"ImportTable RVA",           4}, {"ImportTable Size",           4},
		{"ResourceTable RVA",         4}, {"ResourceTable Size",         4},
		{"ExceptionTable RVA",        4}, {"ExceptionTable Size",        4},
		{"CertificateTable RVA",      4}, {"CertificateTable Size",      4},
		{"BaseRelocationTable RVA",   4}, {"BaseRelocationTable Size",   4},
		{"Debug RVA",                 4}, {"Debug Size",                 4},
		{"Architecture RVA",          4}, {"Architecture Size",          4},
		{"GlobalPointer RVA",         4}, {"GlobalPointer Size",         4},
		{"TLSTable RVA",              4}, {"TLSTable Size",              4},
		{"LoadConfigTable RVA",       4}, {"LoadConfigTable Size",       4},
		{"BoundImport RVA",           4}, {"BoundImport Size",           4},
		{"IAT RVA",                   4}, {"IAT Size",                   4},
		{"DelayImportDescriptor RVA", 4}, {"DelayImportDescriptor Size", 4},
		{"CLRRuntimeHeader RVA",      4}, {"CLRRuntimeHeader Size",      4},
		{"Reserved RVA",              4}, {"Reserved Size",              4},
	}

	scnHdNmSz = [...]nmSzPair{
		{"SectionName",          8}, {"VirtualSize",         4}, {"VirtualAddress",       4},
		{"SizeOfRawData",        4}, {"PointerToRawData",    4}, {"PointerToRelocations", 4},
		{"PointerToLinenumbers", 4}, {"NumberOfRelocations", 2}, {"NumberOfLinenumbers",  2},
		{"Characteristics",      4},
	}

	iidNmSz = [...]nmSzPair{
		{"OriginalFirstThunk", 4}, {"TimeDateStamp", 4}, {"ForwarderChain", 4},
		{"Name",               4}, {"FirstThunk",    4},
	}

	exptTblNmSz = [...]nmSzPair{
		{"Characteristics",    4}, {"TimeDateStamp",  4}, {"MajorVersion",          2}, {"MinorVersion",  2},
		{"Name",               4}, {"Base",           4}, {"NumberOfFunctions",     4}, {"NumberOfNames", 4},
		{"AddressOfFunctions", 4}, {"AddressOfNames", 4}, {"AddressOfNameOrdinals", 4},
	}

	machNumVal = map[uint16]string{
		0x0000: "IMAGE_FILE_MACHINE_UNKNOWN", 0x014C: "IMAGE_FILE_MACHINE_I386",      0x0162: "IMAGE_FILE_MACHINE_R3000",
		0x0166: "IMAGE_FILE_MACHINE_R4000",   0x0168: "IMAGE_FILE_MACHINE_R10000",    0x0169: "IMAGE_FILE_MACHINE_WCEMIPSV2",
		0x0184: "IMAGE_FILE_MACHINE_ALPHA",   0x01A2: "IMAGE_FILE_MACHINE_SH3",       0x01A3: "IMAGE_FILE_MACHINE_SH3DSP",
		0x01A4: "IMAGE_FILE_MACHINE_SH3E",    0x01A6: "IMAGE_FILE_MACHINE_SH4",       0x01A8: "IMAGE_FILE_MACHINE_SH5",
		0x01C0: "IMAGE_FILE_MACHINE_ARM",     0x01C2: "IMAGE_FILE_MACHINE_THUMB",     0x01C4: "IMAGE_FILE_MACHINE_ARMNT",
		0x01D3: "IMAGE_FILE_MACHINE_AM33",    0x01F0: "IMAGE_FILE_MACHINE_POWERPC",   0x01F1: "IMAGE_FILE_MACHINE_POWERPCFP",
		0x0200: "IMAGE_FILE_MACHINE_IA64",    0x0266: "IMAGE_FILE_MACHINE_MIPS16",    0x0284: "IMAGE_FILE_MACHINE_ALPHA64",
		0x0366: "IMAGE_FILE_MACHINE_MIPSFPU", 0x0466: "IMAGE_FILE_MACHINE_MIPSFPU16", 0x0520: "IMAGE_FILE_MACHINE_TRICORE",
		0x0CEF: "IMAGE_FILE_MACHINE_CEF",     0x0EBC: "IMAGE_FILE_MACHINE_EBC",       0x8664: "IMAGE_FILE_MACHINE_AMD64",
		0x9041: "IMAGE_FILE_MACHINE_M32R",    0xC0EE: "IMAGE_FILE_MACHINE_CEE",
	}

	subsysNumVal = map[uint16]string{
		0x00: "IMAGE_SUBSYSTEM_UNKNOWN",            0x01: "IMAGE_SUBSYSTEM_NATIVE",
		0x02: "IMAGE_SUBSYSTEM_WINDOWS_GUI",        0x03: "IMAGE_SUBSYSTEM_WINDOWS_CUI",
		0x05: "IMAGE_SUBSYSTEM_OS2_CUI",            0x07: "IMAGE_SUBSYSTEM_POSIX_CUI",
		0x08: "IMAGE_SUBSYSTEM_NATIVE_WINDOWS",     0x09: "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
		0x0A: "IMAGE_SUBSYSTEM_EFI_APPLICATION",    0x0B: "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
		0x0C: "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER", 0x0D: "IMAGE_SUBSYSTEM_EFI_ROM",
		0x0E: "IMAGE_SUBSYSTEM_XBOX",               0x10: "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION",
	}

	flHdCharacters = map[uint16]string{
		0x0: "IMAGE_FILE_RELOCS_STRIPPED",    0x1: "IMAGE_FILE_EXECUTABLE_IMAGE",
		0x2: "IMAGE_FILE_LINE_NUMS_STRIPPED", 0x3: "IMAGE_FILE_LOCAL_SYMS_STRIPPED",
		0x4: "IMAGE_FILE_AGGRESIVE_WS_TRIM",  0x5: "IMAGE_FILE_LARGE_ADDRESS_AWARE",
		0x6: "IMAGE_FILE_BYTES_REVERSED_LO",  0x8: "IMAGE_FILE_32BIT_MACHINE",
		0x9: "IMAGE_FILE_DEBUG_STRIPPED",     0xA: "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP",
		0xB: "IMAGE_FILE_NET_RUN_FROM_SWAP",  0xC: "IMAGE_FILE_SYSTEM",
		0xD: "IMAGE_FILE_DLL",                0xE: "IMAGE_FILE_UP_SYSTEM_ONLY",
		0xF: "IMAGE_FILE_BYTES_REVERSED_HI",
	}

	scnHdCharacters = map[uint16]string{
		0x05: "IMAGE_SCN_CNT_CODE",               0x06: "IMAGE_SCN_CNT_INITIALIZED_DATA",
		0x07: "IMAGE_SCN_CNT_UNINITIALIZED_DATA", 0x09: "IMAGE_SCN_LNK_INFO",
		0x0B: "IMAGE_SCN_LNK_REMOVE",             0x0C: "IMAGE_SCN_LNK_COMDAT",
		0x0E: "IMAGE_SCN_NO_DEFER_SPEC_EXC",      0x0F: "IMAGE_SCN_GPREL",
		0x18: "IMAGE_SCN_LNK_NRELOC_OVFL",        0x19: "IMAGE_SCN_MEM_DISCARDABLE",
		0x1a: "IMAGE_SCN_MEM_NOT_CACHED",         0x1B: "IMAGE_SCN_MEM_NOT_PAGED",
		0x1C: "IMAGE_SCN_MEM_SHARED",             0x1D: "IMAGE_SCN_MEM_EXECUTE",
		0x1E: "IMAGE_SCN_MEM_READ",               0x1F: "IMAGE_SCN_MEM_WRITE",
	}
)

func ParseCharacteristics[T uint16 | uint32](val T) (result []T) {
	for fltr := T(1); fltr != 0; fltr <<= 1 {
		if val & fltr != 0 {
			result = append(result, fltr)
		}
	}

	return
}

func getCharacteristicsVal(val any) string {
	builder := new(strings.Builder)

	var floatChars []float64
	var ptrChars   *map[uint16]string

	switch v := val.(type) {
	case uint16:
		ptrChars   = &flHdCharacters
		floatChars = Map(
			ParseCharacteristics(v),
			func(x uint16) float64 { return float64(x) },
		)
	case uint32:
		ptrChars   = &scnHdCharacters
		floatChars = Map(
			ParseCharacteristics(v),
			func(x uint32) float64 { return float64(x) },
		)
	default:
		panic("data type for unintended parameters")
	}

	for _, v := range floatChars {
		builder.WriteString((*ptrChars)[uint16(math.Log2(v))])
		builder.WriteRune('\n')
	}

	return builder.String()
}

func getScnOfEachDataDir(pe *PeHeader) []int {
	result := make([]int, len(pe.dataDirectory.elems) >> 1)

	for i, v := range pe.dataDirectory.elems {
		if i & 1 == 0 {
			result[i >> 1] = GetEnclosingSection(v.data, pe.sectionHeaders)
		}
	}

	return result
}

func parseIAT(pe *PeHeader, wholeFl []byte) *ImportTable {
	getLibName   := func(addr uint) string {
		return GetString(wholeFl[pe.RvaToRaw(addr):])
	}
	imptTbl      := &ImportTable{
		offset: pe.dataDirectory.elems[2].data,
		size:   pe.dataDirectory.elems[3].data,
	}

	if imptTbl.offset == 0 || imptTbl.size == 0 {
		return &ImportTable{}
	}

	for rOffset := pe.RvaToRaw(imptTbl.offset); Bytes2uint(Sub(wholeFl[rOffset:], 4)) != 0; rOffset += 20 {
		iid   := &ImageImportDescriptor{
			Header: *parseOneHeader(rOffset, 20, wholeFl, iidNmSz[:], func(i int, d uint) string {
				switch i {
				case 3:  return getLibName(d)
				default: return ""
				}
			}),
		}
		oThnk := pe.RvaToRaw(iid.elems[0].data)
		thnk  := iid.elems[4].data

		for {
			imgImptByNmptrRVA := Bytes2uint(Sub(wholeFl[oThnk:], 4))
			imgImptByNmPtr    := pe.RvaToRaw(imgImptByNmptrRVA)

			if imgImptByNmptrRVA == 0 {
				break
			}

			iid.info = append(iid.info, &TblInfo{
				ordinal: uint16(Bytes2uint(Sub(wholeFl[imgImptByNmPtr:], 2))),
				name:    GetString(wholeFl[imgImptByNmPtr+2:]),
				rva:     uint32(thnk),
			})

			oThnk += 4
			thnk  += 4
		}

		imptTbl.iids = append(imptTbl.iids, iid)
	}

	return imptTbl
}

func parseEAT(pe *PeHeader, wholeFl []byte) *ExportTable {
	offset  := pe.RvaToRaw(pe.dataDirectory.elems[0].data)
	size    := pe.dataDirectory.elems[1].data
	getName := func(addr uint) string {
		return GetString(wholeFl[pe.RvaToRaw(addr):])
	}

	if offset == 0 || size == 0 {
		return &ExportTable{}
	}

	exptTbl      := &ExportTable{
		Header: *parseOneHeader(offset, size, wholeFl, exptTblNmSz[:], func(i int, d uint) string {
			switch i {
			case 4:  return getName(d)
			default: return ""
			}
		}),
	}
	addrOfFuncs  := pe.RvaToRaw(exptTbl.elems[8].data)
	addrOfNames  := pe.RvaToRaw(exptTbl.elems[9].data)
	addrOfNmOrds := pe.RvaToRaw(exptTbl.elems[10].data)

	for i := uint(0); i < exptTbl.elems[7].data; i++ {
		name := getName(Bytes2uint(Sub(wholeFl[addrOfNames:], 4)))
		ord  := uint16(Bytes2uint(Sub(wholeFl[addrOfNmOrds:], 2)))
		rva  := uint32(Bytes2uint(Sub(wholeFl[addrOfFuncs + 4 * uint(ord):], 4)))

		exptTbl.info = append(exptTbl.info, &TblInfo{ordinal: ord, name: name, rva: rva})

		addrOfNames  += 4
		addrOfNmOrds += 2
	}

	return exptTbl
}

func parseOneHeader(offset, sz uint, wholeFl []byte, nmSz []nmSzPair, getVal func(int, uint) string) *Header {
	header := &Header{offset: offset, size: sz}
	slice  := wholeFl[offset:]
	addr   := uint8(0)

	for i := 0; i < len(nmSz); i++ {
		data := Bytes2uint(Sub(slice[addr:], nmSz[i].sz))

		header.elems = append(header.elems, &ElemDetails{
			name: nmSz[i].nm,
			size: nmSz[i].sz,
			addr: addr,
			data: data,
			val:  getVal(i, data),
		})

		addr += nmSz[i].sz
	}

	return header
}

func ParsePE(wholeFile []byte, sys int8) *PeHeader {
	pe          := new(PeHeader)
	offset      := uint(0)
	parseHeader := func(o, s uint, ns []nmSzPair, getV func(int, uint) string) *Header {
		return parseOneHeader(o, s, wholeFile, ns, getV)
	}

	pe.dosHeader = parseHeader(offset, 0x40, dosHdNmSz[:], func(i int, _ uint) string {
		switch i {
		case 0:  return "PE file"
		default: return ""
		}
	})

	offset        = pe.dosHeader.elems[len(dosHdNmSz)-1].data + 4
	pe.fileHeader = parseHeader(offset, 0x14, flHdNmSz[:], func(i int, d uint) string {
		switch i {
		case 0:  return machNumVal[uint16(d)]
		case 2:  return time.Unix(int64(d), 0).String()
		case 6:  return getCharacteristicsVal(uint16(d))
		default: return ""
		}
	})

	szOfOpHd  := uint(0x70)
	nmSzSlice := opHd64NmSz[:]
	subsysIdx := 21

	if sys == x86 {
		szOfOpHd  = 0x60
		nmSzSlice = opHd32NmSz[:]
		subsysIdx = 22
	}

	offset            = pe.fileHeader.offset + pe.fileHeader.size
	pe.optionalHeader = parseHeader(offset, szOfOpHd, nmSzSlice, func(i int, d uint) string {
		switch i {
		case subsysIdx:
			return subsysNumVal[uint16(d)]
		case 0:
			switch d {
			case 0x10B: return "PE32"
			case 0x20B: return "PE32+"
			}
			fallthrough
		default:
			return ""
		}
	})

	offset           = pe.optionalHeader.offset + pe.optionalHeader.size
	pe.dataDirectory = parseHeader(offset, 0x80, dataDirNmSz[:], func(_ int, _ uint) string { return "" })

	offset            = pe.dataDirectory.offset + pe.dataDirectory.size
	pe.sectionHeaders = make([]*Header, pe.fileHeader.elems[1].data)

	for i := 0; i < len(pe.sectionHeaders); i++ {
		pe.sectionHeaders[i] = parseHeader(offset, 0x28, scnHdNmSz[:], func(i int, d uint) string {
			switch i {
			case 0:  return string(Uint2bytes(d, 8))
			case 9:  return getCharacteristicsVal(uint32(d))
			default: return ""
			}
		})

		offset += pe.sectionHeaders[i].size
	}

	return pe
}
