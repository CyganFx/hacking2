package main

import (
	"github.com/google/gopacket/pcap"
	"time"
)

var (
	device        = "en0"
	snaplen int32 = 65535
	promisc       = false
	err     error
	timeout = -1 * time.Second
)

func main() {
	//handle, err = pcap.OpenLive()
}
