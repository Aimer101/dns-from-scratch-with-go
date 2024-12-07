package main

import (
	"encoding/binary"
)

func UintToBigEndian[T uint16 | uint32](num T) []byte {

	var bytes []byte

	switch any(num).(type) {
	case uint16:
		bytes = make([]byte, 2)
		binary.BigEndian.PutUint16(bytes, uint16(num))

	case uint32:
		bytes = make([]byte, 4)
		binary.BigEndian.PutUint32(bytes, uint32(num))

	default:
		panic("unsupported type")
	}

	return bytes

}
