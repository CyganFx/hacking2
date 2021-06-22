package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"log"
	"os"
	"time"
)

var (
	pcapFile       = "test.pcap"
	device         = "wlp2s0"
	snaplen  int32 = 65535
	promisc        = false
	err      error
	timeout  = -1 * time.Second
	handle   *pcap.Handle
)

func main() {
	f, _ := os.Create("test.pcap")
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(uint32(snaplen), layers.LinkTypeEthernet)
	defer f.Close()

	handle, err := pcap.OpenLive(device, snaplen, promisc, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	filter := "src host info.cern.ch"
	if err = handle.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	fmt.Println("filter was set")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	// Loop through packets in file
	for packet := range packetSource.Packets() {
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		ip_packet, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		fmt.Println("SRC:", ip_packet.SrcIP.String())
		//fmt.Println("Data:", string(packet.Data()))

		fmt.Println("Payload: ", ip_packet.Payload)
	}

	//resp, _ := http.Get("http://info.cern.ch/")
	//dump, _ := httputil.DumpResponse(resp, true)
	//fmt.Println(string(dump))

}
