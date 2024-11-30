package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// Construct the DNS header
// Fields:
// ============= 2 bytes ================
// ID = 1234, 16 bits
// ============= 1 byte ================
// QR = 1, 1 bit
// OPCODE = 0, 4 bits
// AA = 0, 1 bit
// TC = 0, 1 bit
// RD = 0, 1 bit
// ============= 1 byte ================
// RA = 0, 1 bit
// Z = 0, 3 bits
// RCODE = 0, 4 bits
// ============= 2 bytes ================
// QDCOUNT = 16 bits
// ============= 2 bytes ================
// ANCOUNT = 16 bits
// ============= 2 bytes ================
// NSCOUNT = 16 bits
// ============= 2 bytes ================
// ARCOUNT = 16 bits
//
//	type DnsHeaderDTO struct {
//		ID      uint16
//		QR      uint8 // 1 bit
//		OP      uint8 // 4 bits
//		AA      uint8 // 1 bit
//		TC      uint8 // 1 bit
//		RD      uint8 // 1 bit
//		RA      uint8 // 1 bit
//		Z       uint8 // 3 bits
//		RCODE   uint8 // 4 bits
//		QDCOUNT uint16
//		ANCOUNT uint16
//		NSCOUNT uint16
//		ARCOUNT uint16
//	}
type DnsHeaderDTO struct {
	ID             uint16
	QR_OP_AA_TC_RD uint8
	RA_Z_RCODE     uint8
	QDCOUNT        uint16
	ANCOUNT        uint16
	NSCOUNT        uint16
	ARCOUNT        uint16
}

type DnsHeader struct {
	ID      uint16
	QR      uint8 // 1 bit
	OP_CODE uint8 // 4 bits
	AA      uint8 // 1 bit
	TC      uint8 // 1 bit
	RD      uint8 // 1 bit
	RA      uint8 // 1 bit
	Z       uint8 // 3 bits
	RCODE   uint8 // 4 bits
	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
}

func (d *DnsHeader) EncodeHeaderDTO() []byte {
	// The first byte will hold QR, OP_CODE, AA, TC, RD, RA, Z, and RCODE
	var flags uint16

	// Packing the bits from struct fields into the flags byte.
	// QR (1 bit)
	flags |= uint16(d.QR) << 15 // QR is the highest bit (bit 15)

	// OPCODE (4 bits)
	flags |= uint16(d.OP_CODE) << 11 // OPCODE is next (bits 11-14)

	// AA (1 bit)
	flags |= uint16(d.AA) << 10 // AA is at bit 10

	// TC (1 bit)
	flags |= uint16(d.TC) << 9 // TC is at bit 9

	// RD (1 bit)
	flags |= uint16(d.RD) << 8 // RD is at bit 8

	// RA (1 bit)
	flags |= uint16(d.RA) << 7 // RA is at bit 7

	// Z (3 bits)
	flags |= uint16(d.Z) << 4 // Z is at bits 4-6

	// RCODE (4 bits)
	flags |= uint16(d.RCODE) // RCODE is at bits 0-3

	payload := DnsHeaderDTO{
		ID:             d.ID,
		QR_OP_AA_TC_RD: uint8(flags >> 8),
		RA_Z_RCODE:     uint8(flags & 0xFF),
		QDCOUNT:        d.QDCOUNT,
		ANCOUNT:        d.ANCOUNT,
		NSCOUNT:        d.NSCOUNT,
		ARCOUNT:        d.ARCOUNT,
	}

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, payload)

	if err != nil {
		fmt.Println("Failed to encode DNS header:", err)
	}

	// Return the packed flag byte
	return buf.Bytes()
}

func main() {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}

	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		_, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		requestHeaders := encodeHeader(buf[:12])

		var rcode uint8

		if requestHeaders.OP_CODE == 0 {
			rcode = 0
		} else {
			rcode = 4
		}

		responseHeader := DnsHeader{
			ID:      requestHeaders.ID,
			QR:      1,
			OP_CODE: requestHeaders.OP_CODE,
			AA:      0,
			TC:      0,
			RD:      requestHeaders.RD,
			RA:      0,
			Z:       0,
			RCODE:   rcode,
			QDCOUNT: 1,
			ANCOUNT: 1,
			NSCOUNT: 0,
			ARCOUNT: 0,
		}

		headers := responseHeader.EncodeHeaderDTO()

		questions := []byte{}

		parsedDomain := ParseQuestion(buf[12:])
		byteDomain := ParseString(parsedDomain)

		// questions section
		questions = append(questions, byteDomain...)
		questions = append(questions, ParseBigEndianUint(uint16(1))...) //  Type: 2-byte int; the type of record (1 for an A record, 5 for a CNAME record etc.,
		questions = append(questions, ParseBigEndianUint(uint16(1))...) // Class : 2-byte int; usually set to 1

		// answers section
		answer := []byte{}
		answer = append(answer, byteDomain...)
		answer = append(answer, ParseBigEndianUint(uint16(1))...)  //  Type: 2-byte int; the type of record (1 for an A record, 5 for a CNAME record etc.,
		answer = append(answer, ParseBigEndianUint(uint16(1))...)  // Class : 2-byte int; usually set to 1
		answer = append(answer, ParseBigEndianUint(uint32(60))...) // TTL	Any value, encoded as a 4-byte big-endian int. For example: 60.
		answer = append(answer, ParseBigEndianUint(uint16(4))...)  // Length 4, encoded as a 2-byte big-endian int (corresponds to the length of the RDATA field)
		answer = append(answer, ParseString("8.8.8.8")...)         //Any IP address, encoded as a 4-byte big-endian int. For example: \x08\x08\x08\x08 (that's 8.8.8.8 encoded as a 4-byte integer)

		fullContent := append(headers[:], questions...)
		fullContent = append(fullContent, answer...)

		_, err = udpConn.WriteToUDP(fullContent, source)

		if err != nil {
			fmt.Println("Failed to send response:", err)
		}

	}
}

func encodeHeader(request []byte) DnsHeader {
	if len(request) < 12 {
		panic("incorrect packet size")
	}

	var parsedRequest DnsHeaderDTO

	err := binary.Read(bytes.NewReader(request), binary.BigEndian, &parsedRequest)

	if err != nil {
		panic(err)
	}

	return DnsHeader{
		ID:      parsedRequest.ID,
		QR:      parsedRequest.QR_OP_AA_TC_RD >> 7 & 1,
		OP_CODE: parsedRequest.QR_OP_AA_TC_RD >> 3 & 15,
		AA:      parsedRequest.QR_OP_AA_TC_RD >> 2 & 1,
		TC:      parsedRequest.QR_OP_AA_TC_RD >> 1 & 1,
		RD:      parsedRequest.QR_OP_AA_TC_RD & 1,
		RA:      parsedRequest.RA_Z_RCODE >> 7 & 1,
		Z:       parsedRequest.RA_Z_RCODE >> 3 & 7,
		RCODE:   parsedRequest.RA_Z_RCODE & 15,
		QDCOUNT: parsedRequest.QDCOUNT,
		ANCOUNT: parsedRequest.ANCOUNT,
		NSCOUNT: parsedRequest.NSCOUNT,
		ARCOUNT: parsedRequest.ARCOUNT,
	}

}

func ParseBigEndianUint[T uint16 | uint32](num T) []byte {

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

func ParseQuestion(request []byte) string {
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
