package main

import (
	"encoding/binary"
	"fmt"
	"net"
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
		// ID = 1234 (0x04D2),
		// QR = 1,
		// OPCODE = 0,
		// AA = 0,
		// TC = 0,
		// RD = 0
		// RA = 0,
		// Z = 0,
		// RCODE = 0,
		// QDCOUNT = 0,
		// ANCOUNT = 0,
		// NSCOUNT = 0,
		// ARCOUNT = 0

		headers := [12]byte{}

		// 2 bytes of id
		binary.BigEndian.PutUint16(headers[:2], 1234) // ID = 1234 (0x04D2),

		// 1 byte of QR, OPCODE, AA, TC, RD AND
		headers[2] = (1 << 7) | // qr msb
			(0 << 3) | // opcode 3 msb
			(0 << 2) | // aa // 2 msb
			(0 << 2) | // tc
			(0 << 1) // rd

		// rest is 0
		headers[3] = 0

		_, err = udpConn.WriteToUDP(headers[:], source)

		if err != nil {
			fmt.Println("Failed to send response:", err)
		}

	}

}
