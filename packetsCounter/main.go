package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
)

var (
	pcapFile = "./http.cap"
)

func main() {
	tcpPacketsCounter := 0
	udpPacketsCounter := 0
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
			tcpPacketsCounter++
		} else if packet.TransportLayer().LayerType() == layers.LayerTypeUDP {
			udpPacketsCounter++
		}
	}

	fmt.Printf("Total amount of tcp packets in a dump: %d\n", tcpPacketsCounter)
	fmt.Printf("Total amount of udp packets in a dump: %d\n", udpPacketsCounter)
}
