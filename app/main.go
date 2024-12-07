package main

import (
	"flag"
	"fmt"
	"net"
)

func main() {

	// Parse resolver address from command line
	resolverAddr := flag.String("resolver", "", "DNS resolver address (ip:port)")
	flag.Parse()

	// Resolve remote resolver address
	remoteServerAddr, err := net.ResolveUDPAddr("udp", *resolverAddr)

	if err != nil {
		fmt.Println("Failed to resolve resolver address:", err)
		return
	}

	fmt.Println("Resolver address is:", *resolverAddr)

	localAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	localConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}

	defer localConn.Close()

	buf := make([]byte, 512)

	for {
		size, client, err := localConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		parsedPacket := buf[:size]

		go forwardToRemoteServer(parsedPacket, client, localConn, remoteServerAddr)

		// data := CreateNewDnsMessage(parsedPacket)

		// _, err = localConn.WriteToUDP(data.serialize(), client)

		// if err != nil {
		// 	fmt.Println("Failed to send response:", err)
		// }

	}
}

func forwardToRemoteServer(clientPacket []byte, client *net.UDPAddr, localConn *net.UDPConn, remoteServerAddr *net.UDPAddr) {
	// Forward query to resolver
	remoteConn, err := net.DialUDP("udp", nil, remoteServerAddr)
	if err != nil {
		fmt.Println("Failed to connect to resolver:", err)
		return
	}
	defer remoteConn.Close()

	_, err = remoteConn.Write(clientPacket)
	if err != nil {
		fmt.Println("Failed to forward query:", err)
		return
	}

	// Response from resolver
	remoteServerResponsePacket := make([]byte, 512)
	size, err := remoteConn.Read(remoteServerResponsePacket)
	if err != nil {
		fmt.Println("Failed to read resolver response:", err)
		return
	}

	parsedPacket := remoteServerResponsePacket[:size]

	data := CreateNewDnsMessage(parsedPacket, clientPacket)
	_, err = localConn.WriteToUDP(data.serialize(), client)

	if err != nil {
		fmt.Println("Failed to send response:", err)
	}

}
