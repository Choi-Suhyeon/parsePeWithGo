package main

import (
	"errors"
	"bytes"
	"time"
	"fmt"
	"os"
)

func getFileBytes(filename string) ([]byte, error) {
	if fl, err := os.ReadFile(filename); err == nil {
		return fl, nil
	}

	return nil, errors.New("failed to open file")
}

type executableChecker interface {
	check([]byte) (bool, int)
}

type whetherPE struct{}

func (w *whetherPE) check(wholeBytes []byte) (bool, int8) {
	const (
		x86Sz = 0xE0
		x64Sz = 0xF0
	)

	sig := [2][]byte{{0x4D, 0x5A}, {0x5A, 0x4D}}

	if bytes.HasPrefix(wholeBytes, sig[0]) || bytes.HasPrefix(wholeBytes, sig[1]) {
		addrOfSzOfOpHd := Bytes2uint(Sub(wholeBytes[0x3C:], 4)) + 0x14
		SzOfOpHd       := Bytes2uint(Sub(wholeBytes[addrOfSzOfOpHd:], 2))

		switch SzOfOpHd {
		case x86Sz: return true, x86
		case x64Sz: return true, x64
		default:
		}
	}

	return false, -1
}

func main() {
	file, err := getFileBytes("PEView.exe")
	if err != nil {
		fmt.Println("No way~")
		return
	}

	ok, os := new(whetherPE).check(file)
	if ok {
		start := time.Now()
		pe := ParsePE(file, os)
		fmt.Println(time.Since(start))
		/*
		for _, v := range pe.dosHeader.elems {
			fmt.Println(v)
		}
		fmt.Println()
		for _, v := range pe.fileHeader.elems {
			fmt.Println(v)
		}
		fmt.Println()
		for _, v := range pe.optionalHeader.elems {
			fmt.Println(v)
		}
		fmt.Println()
		for _, v := range pe.dataDirectory.elems {
			fmt.Println(v)
		}
		fmt.Println()
		for _, v := range pe.sectionHeaders {
			fmt.Println(v.offset)
			fmt.Println(v.size)
			for _, u := range v.elems {
				fmt.Println(u)
			}
			fmt.Println()
		}
		fmt.Println()*/
		temp1 := parseIAT(pe, file)
		fmt.Printf("%d %d\n", temp1.offset, temp1.size)
		for _, v := range temp1.iids {
			fmt.Println(v.offset)
			fmt.Println(v.size)
			fmt.Println()
			for _, u := range v.elems {
				fmt.Println(u)
			}
			fmt.Println()
			for _, u := range v.info {
				fmt.Println(u)
			}
			fmt.Println()
			fmt.Println()
		}
	}
}
