package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

var _ = net.ListenUDP

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
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

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
		// QDCOUNT = 0, 16 bits
		// ============= 2 bytes ================
		// ANCOUNT = 0, 16 bits
		// ============= 2 bytes ================
		// NSCOUNT = 0, 16 bits
		// ============= 2 bytes ================
		// ARCOUNT = 0 16 bits

		headers := [12]byte{}

		// 2 bytes of id
		binary.BigEndian.PutUint16(headers[:2], binary.BigEndian.Uint16(buf[:2])) // ID = 1234 (0x04D2),

		// 1 byte of QR, OPCODE, AA, TC, RD AND
		headers[2] = (1 << 7) | // qr msb
			(0 << 3) | // opcode 3 msb
			(0 << 2) | // aa // 2 msb
			(0 << 2) | // tc
			(0 << 1) // rd

		headers[3] = 0

		binary.BigEndian.PutUint16(headers[4:6], uint16(1))
		binary.BigEndian.PutUint16(headers[6:8], 0)
		binary.BigEndian.PutUint16(headers[8:10], 0)
		binary.BigEndian.PutUint16(headers[10:12], 0)

		questions := []byte{}

		// questions section
		questions = append(questions, ParseString("codecrafters.io")...)
		questions = append(questions, ParseBigEndianUint16(1)...) // type
		questions = append(questions, ParseBigEndianUint16(1)...) // class

		fullContent := append(headers[:], questions...)

		_, err = udpConn.WriteToUDP(fullContent, source)

		if err != nil {
			fmt.Println("Failed to send response:", err)
		}

	}
}

func ParseBigEndianUint16(num uint16) []byte {
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, uint16(num))

	return []byte(bytes)
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
