package main

import "math"

const (
	x86 int8 = iota
	x64
)

func Sub[T any](arr []T, size uint8) []T {
	return arr[:size]
}

func Map[T, F any](arr[]T, fn func(T)F) []F {
	result := make([]F, len(arr))

	for i, v := range arr {
		result[i] = fn(v)
	}

	return result
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

type ElemDetails struct {
	size uint8
	addr uint8
	data uint
	name string
	val  string
}

func (e *ElemDetails) GetSize() uint8 {
	return e.size
}

func (e *ElemDetails) GetAddr() uint8 {
	return e.addr
}

func (e *ElemDetails) GetName() string {
	return e.name
}

func (e *ElemDetails) GetValue() string {
	return e.val
}

func (e *ElemDetails) GetData() uint {
	return e.data
}

type Header struct {
	offset uint
	size   uint
	Elems  []*ElemDetails
}

func (h *Header) GetOffset() uint {
	return h.offset
}

func (h *Header) GetSize() uint {
	return h.size
}