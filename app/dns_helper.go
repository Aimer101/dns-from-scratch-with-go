package main

import (
	"bytes"
	"encoding/binary"
	"strings"
)

func unmarshalHeader(buffer []byte) DnsHeader {
	return DnsHeader{
		ID:      binary.BigEndian.Uint16(buffer[0:2]),
		QR:      buffer[2] >> 7 & 1,
		OP_CODE: buffer[2] >> 3 & 15,
		AA:      buffer[2] >> 2 & 1,
		TC:      buffer[2] >> 1 & 1,
		RD:      buffer[2] & 1,
		RA:      buffer[3] >> 7 & 1,
		Z:       buffer[3] >> 3 & 7,
		RCODE:   buffer[3] & 15,
		QDCOUNT: binary.BigEndian.Uint16(buffer[4:6]),
		ANCOUNT: binary.BigEndian.Uint16(buffer[6:8]),
		NSCOUNT: binary.BigEndian.Uint16(buffer[8:10]),
		ARCOUNT: binary.BigEndian.Uint16(buffer[10:12]),
	}
}

// In practice only a single question indicating
// the query name (domain) and the record type of interest.
// Domain names in DNS packets are encoded as a sequence of labels.
// Labels are encoded as <length><content>, where <length> is a single byte that specifies the length of the label,
// and <content> is the actual content of the label.
// The sequence of labels is terminated by a null byte (\x00).
// google.com is encoded as
// \x06google\x03com\x00 (in hex: 06 67 6f 6f 67 6c 65 03 63 6f 6d 00)

// 20 |           1           |           F           |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 22 |           3           |           I           |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 24 |           S           |           I           |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 26 |           4           |           A           |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 28 |           R           |           P           |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 30 |           A           |           0           |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 40 |           3           |           F           |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 42 |           O           |           O           |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 44 | 1  1|                20                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 64 | 1  1|                26                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 92 |           0           |                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// The domain name for F.ISI.ARPA is shown at offset 20.  The domain name
// FOO.F.ISI.ARPA is shown at offset 40; this definition uses a pointer to
// concatenate a label for FOO to the previously defined F.ISI.ARPA.  The
// domain name ARPA is defined at offset 64 using a pointer to the ARPA
// component of the name F.ISI.ARPA at 20; note that this pointer relies on
// ARPA being the last label in the string at 20.
func uncompressLabel(processedPacket []byte, originalPacket []byte) string {
	// label example are www google com
	labels := []string{}

	offset := 0

	for offset < len(processedPacket) {
		if processedPacket[offset] == 0 {
			break
		}
		// The pointer takes the form of a two octet sequence:
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		// | 1  1|                OFFSET                   |
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		// The first two bits are ones.  This allows a pointer to be distinguished
		// from a label, since the label must begin with two zero bits because
		// labels are restricted to 63 octets or less.  (The 10 and 01 combinations
		// are reserved for future use.)  The OFFSET field specifies an offset from
		// the start of the message (i.e., the first octet of the ID field in the
		// domain header).  A zero offset specifies the first byte of the ID field,
		// etc.

		if processedPacket[offset]>>6 == 0b11 {
			pointer := binary.BigEndian.Uint16(processedPacket[offset : offset+2])
			pointer = pointer << 2
			pointer = pointer >> 2

			size := bytes.Index(originalPacket[pointer:], []byte{0})

			labels = append(labels, uncompressLabel(originalPacket[offset:offset+size+1], originalPacket))

			offset += 2
			continue
		}

		size := int(processedPacket[offset])
		substring := processedPacket[offset+1 : offset+1+size]

		labels = append(labels, string(substring))

		offset = offset + 1 + size
	}

	return strings.Join(labels, ".")
}

// Each question has the following structure:
// Name: A domain name, represented as a sequence of "labels" (more on this below)
// Type: 2-byte int; the type of record (1 for an A record, 5 for a CNAME record etc., full list here)
// Class: 2-byte int; usually set to 1 (full list here)
func unmarshalQuestions(packet []byte, nQuestions int) ([]DnsQuestion, int) {
	// label example are www google com
	questions := []DnsQuestion{}

	offset := 0

	for i := 0; i < nQuestions; i++ {
		size := bytes.Index(packet[offset:], []byte{0})

		label := uncompressLabel(packet[offset:offset+size+1], packet)

		questions = append(questions, DnsQuestion{
			Name:  label,
			Type:  1,
			Class: 1,
		})

		offset += size + 1
		offset += 2 //Type: 2-byte int
		offset += 2 // Class: 2-byte int;
	}

	return questions, offset
}

// Name	\x0ccodecrafters\x02io followed by a null byte (that's codecrafters.io encoded as a label sequence)
// Type	1 encoded as a 2-byte big-endian int (corresponding to the "A" record type)
// Class	1 encoded as a 2-byte big-endian int (corresponding to the "IN" record class)
// TTL	Any value, encoded as a 4-byte big-endian int. For example: 60.
// Length	4, encoded as a 2-byte big-endian int (corresponds to the length of the RDATA field)
// Data	Any IP address, encoded as a 4-byte big-endian int. For example: \x08\x08\x08\x08 (that's 8.8.8.8 encoded as a 4-byte integer)
func unmarshalAnswers(packet []byte, nAnswer int) []DNSResourceRecords {
	var answers []DNSResourceRecords

	offset := 0

	for i := 0; i < nAnswer; i++ {
		size := bytes.Index(packet[offset:], []byte{0})
		label := uncompressLabel(packet[offset:offset+size+1], packet)
		offset += size + 1

		answerType := binary.BigEndian.Uint16(packet[offset : offset+2])
		offset += 2

		answerClass := binary.BigEndian.Uint16(packet[offset : offset+2])
		offset += 2

		answerTTL := binary.BigEndian.Uint32(packet[offset : offset+4])
		offset += 4

		answerRdlLength := binary.BigEndian.Uint16(packet[offset : offset+2])
		offset += 2

		answerResourceData := packet[offset : offset+4]
		offset += 4

		result := DNSResourceRecords{
			Name:         label,
			Type:         answerType,
			Class:        answerClass,
			TTL:          answerTTL,
			RDLength:     answerRdlLength,
			ResourceData: answerResourceData,
		}

		answers = append(answers, result)

	}

	return answers
}

func CreateNewDnsMessage(remoteServerPacket []byte, clientPacket []byte) DNSMessage {
	query := unmarshalHeader(remoteServerPacket[:12])

	packetToUse := remoteServerPacket

	if query.QDCOUNT == 0 {
		packetToUse = clientPacket
		query = unmarshalHeader(packetToUse[:12])
	}

	questions, size := unmarshalQuestions(packetToUse[12:], int(query.QDCOUNT))
	var answers []DNSResourceRecords

	// if ancount == 0, remote server cannot find it
	// we will create it ourself
	if query.ANCOUNT == 0 {
		for _, q := range questions {
			answers = append(answers, DNSResourceRecords{
				Name:         q.Name,
				Type:         1,
				Class:        1,
				TTL:          0,
				RDLength:     4,
				ResourceData: []byte("\x08\x08\x08\x08"),
			})
		}

	} else {

		answers = unmarshalAnswers(packetToUse[12+size:], int(query.ANCOUNT))
	}

	var rcode uint8

	if query.OP_CODE == 0 {
		rcode = 0
	} else {
		rcode = 4
	}

	headers := DnsHeader{
		ID:      query.ID,
		QR:      1,
		OP_CODE: query.OP_CODE,
		AA:      0,
		TC:      0,
		RD:      query.RD,
		RA:      0,
		Z:       0,
		RCODE:   rcode,
		QDCOUNT: uint16(len(questions)),
		ANCOUNT: uint16(len(answers)),
		NSCOUNT: query.NSCOUNT,
		ARCOUNT: query.ARCOUNT,
	}

	return DNSMessage{
		Header:          headers,
		Questions:       questions,
		ResourceRecords: answers,
	}

}
