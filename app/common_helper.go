package main

import (
	"encoding/binary"
	"strings"
)

func ParseString(domainName string) []byte {
	// split at .
	parts := strings.Split(domainName, ".")

	result := []byte{}

	for _, part := range parts {
		result = append(result, byte(len(part)))
		result = append(result, []byte(part)...)
	}

	result = append(result, '\000')

	return result
}

func MarshalLabels(labels []string) []byte {
	result := []byte{}

	for _, label := range labels {
		result = append(result, ParseString(label)...)
	}

	return result
}

func ParseQuestions(request []byte) string {
	offset := 0

	var result []string

	for offset < len(request) {

		size := int(request[offset])

		if size == 0 {
			break
		}

		offset++

		result = append(result, string(request[offset:offset+size]))
		offset += size
	}

	return strings.Join(result, ".")
}

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
