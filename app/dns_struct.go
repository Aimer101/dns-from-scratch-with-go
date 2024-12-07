package main

import (
	"encoding/binary"
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

func (header *DnsHeader) serialize() []byte {
	buffer := make([]byte, 12)

	binary.BigEndian.PutUint16(buffer[0:2], header.ID)
	buffer[2] = header.QR<<7 | header.OP_CODE<<3 | header.AA<<2 | header.TC<<1 | header.RD
	buffer[3] = header.RA<<7 | header.Z<<3 | header.RCODE
	binary.BigEndian.PutUint16(buffer[4:6], header.QDCOUNT)
	binary.BigEndian.PutUint16(buffer[6:8], header.ANCOUNT)
	binary.BigEndian.PutUint16(buffer[8:10], header.NSCOUNT)
	binary.BigEndian.PutUint16(buffer[10:12], header.ARCOUNT)

	return buffer
}

// Each question has the following structure:
// Name: A domain name, represented as a sequence of "labels" (more on this below)
// Type: 2-byte int; the type of record (1 for an A record, 5 for a CNAME record etc., full list here)
// Class: 2-byte int; usually set to 1 (full list here)
type DnsQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

func (dnsQuestion *DnsQuestion) serialize() []byte {
	buffer := []byte{}

	labels := strings.Split(dnsQuestion.Name, ".")

	for _, label := range labels {
		buffer = append(buffer, byte(len(label)))
		buffer = append(buffer, []byte(label)...)
	}

	buffer = append(buffer, '\000')
	buffer = append(buffer, UintToBigEndian(dnsQuestion.Type)...)  //  Type: 2-byte int; the type of record (1 for an A record, 5 for a CNAME record etc.,
	buffer = append(buffer, UintToBigEndian(dnsQuestion.Class)...) // Class : 2-byte int; usually set to 1

	return buffer

}

type DNSResourceRecords struct {
	Name         string // The domain name being queried.
	Type         uint16 // Record type: 1 = A (IPv4 address).
	Class        uint16 // Class: 1 = IN (Internet).
	TTL          uint32 // Time-to-live: 0 (default, no caching).
	RDLength     uint16 // Length of RData: 4 bytes for IPv4.
	ResourceData []byte //RData contains the IP address in binary format
}

func (dnsAnswer *DNSResourceRecords) serialize() []byte {
	buffer := []byte{}

	labels := strings.Split(dnsAnswer.Name, ".")
	for _, label := range labels {
		buffer = append(buffer, byte(len(label)))
		buffer = append(buffer, []byte(label)...)
	}
	buffer = append(buffer, '\x00')
	buffer = append(buffer, UintToBigEndian(dnsAnswer.Type)...)     //  Type: 2-byte int; the type of record (1 for an A record, 5 for a CNAME record etc.,
	buffer = append(buffer, UintToBigEndian(dnsAnswer.Class)...)    // Class : 2-byte int; usually set to 1
	buffer = append(buffer, UintToBigEndian(dnsAnswer.TTL)...)      // TTL	Any value, encoded as a 4-byte big-endian int. For example: 60.
	buffer = append(buffer, UintToBigEndian(dnsAnswer.RDLength)...) // Length 4, encoded as a 2-byte big-endian int (corresponds to the length of the RDATA field)
	buffer = append(buffer, dnsAnswer.ResourceData...)              //Any IP address, encoded as a 4-byte big-endian int. For example: \x08\x08\x08\x08 (that's 8.8.8.8 encoded as a 4-byte integer)
	return buffer
}

type DNSMessage struct {
	Header          DnsHeader
	Questions       []DnsQuestion
	ResourceRecords []DNSResourceRecords
}

func (dnsMessage *DNSMessage) serialize() []byte {
	buffer := []byte{}
	buffer = append(buffer, dnsMessage.Header.serialize()...)
	for _, question := range dnsMessage.Questions {
		buffer = append(buffer, question.serialize()...)
	}
	for _, resourceRecord := range dnsMessage.ResourceRecords {
		buffer = append(buffer, resourceRecord.serialize()...)
	}
	return buffer
}
