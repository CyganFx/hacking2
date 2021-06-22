package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

var (
	device        = "wlp2s0"
	snaplen int32 = 65535
	promisc       = false
	err     error
	timeout = -1 * time.Second
	handle  *pcap.Handle
)

func main() {
	handle, err := pcap.OpenLive(device, snaplen, promisc, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	//filter := "dst host 192.168.254.99 and icmp"
	filter := "dst host 192.168.254.99"
	if err = handle.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	fmt.Println("filter was set")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	// Loop through packets in file
	for packet := range packetSource.Packets() {
		//ethernet_layer := packet.Layer(layers.LayerTypeEthernet)
		//ethernet_frame := ethernet_layer.(*layers.Ethernet)
		ip_layer := packet.Layer(layers.LayerTypeIPv4)
		ip_packet, _ := ip_layer.(*layers.IPv4)

		//if icmp_packet.TypeCode.String() == "EchoRequest" {
		//	if len(icmp_packet.Payload) > 0 {
		//		log.Println("Info: EchoRequest Received")
		//	} else {
		//		log.Println("Warn: Empty EchoRequest Received")
		//		ethernet_frame_copy := *ethernet_frame
		//		ip_packet_copy := *ip_packet
		//		icmp_packet_copy := *icmp_packet
		//
		//		ethernet_frame_copy.SrcMAC = ethernet_frame.DstMAC
		//		ethernet_frame_copy.DstMAC = ethernet_frame.SrcMAC
		//
		//		ip_packet_copy.SrcIP = ip_packet.DstIP
		//		ip_packet_copy.DstIP = ip_packet.SrcIP
		//
		//		icmp_packet_copy.TypeCode = layers.ICMPv4TypeEchoReply
		//
		//		var buffer gopacket.SerializeBuffer
		//		var options gopacket.SerializeOptions
		//		options.ComputeChecksums = true
		//
		//		buffer = gopacket.NewSerializeBuffer()
		//		gopacket.SerializeLayers(buffer, options,
		//			&ethernet_frame_copy,
		//			&ip_packet_copy,
		//			&icmp_packet_copy,
		//			gopacket.Payload(icmp_packet_copy.Payload),
		//		)
		//
		//		new_message := buffer.Bytes()
		//		err = handle.WritePacketData(new_message)
		//		if err != nil {
		//			log.Fatal(err)
		//		}
		//	}
		//
		//}

		fmt.Println("----------")
		fmt.Println("Source Address: " + ip_packet.SrcIP.String())
		fmt.Println("Destination Address: " + ip_packet.DstIP.String())
		fmt.Println("Protocol: ", ip_packet.Protocol)
		fmt.Println("----------")

	}
}
