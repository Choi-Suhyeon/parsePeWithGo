package main

import (
	"io/ioutil"
	"errors"
	"bytes"
	"fmt"
)

func getFileBytes(filename string) ([]byte, error) {
	fl, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.New("failed to open file")
	}

	return fl, nil
}

type executableChecker interface {
	check([]byte) (bool, int)
}

type whetherPE struct {}

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
		pe := ParsePE(file, os)
		for _, v := range pe.dosHeader.Elems {
			fmt.Println(v)
		}
		fmt.Println()
		for _, v := range pe.fileHeader.Elems {
			fmt.Println(v)
		}
		fmt.Println()
		for _, v := range pe.optionalHeader.Elems {
			fmt.Println(v)
		}
		fmt.Println()
		for _, v := range pe.dataDirectory.Elems {
			fmt.Println(v)
		}
		fmt.Println()
		for _, v := range pe.sectionHeaders {
			fmt.Println(v.offset)
			fmt.Println(v.size)
			for _, u := range v.Elems {
				fmt.Println(u)
			}
			fmt.Println()
		}
		fmt.Println()
	}
}