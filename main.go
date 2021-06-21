package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
)

var (
	pcapFile = "http.cap"
)

func main() {
	packetsCounter := 0
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
		packetsCounter++
	}

	fmt.Printf("Total amount of packets in a dump: %d", packetsCounter)
}
