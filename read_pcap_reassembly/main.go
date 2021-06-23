package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
	"sync"

	//"github.com/google/gopacket/tcpassembly"
	//"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

var (
	pcapFile         string = "infocernch.pcap"
	handle           *pcap.Handle
	err              error
	filter           = flag.String("f", "tcp and port 80", "BPF filter for pcap")
	allowmissinginit = flag.Bool("allowmissinginit", false, "Support streams without SYN/SYN+ACK/ACK sequence")
	hexdump          = flag.Bool("dump", false, "Dump HTTP request/response as hex")
	checksum         = flag.Bool("checksum", false, "Check TCP checksum")
	ignorefsmerr     = flag.Bool("ignorefsmerr", false, "Ignore TCP FSM errors")
	nooptcheck       = flag.Bool("nooptcheck", false, "Do not check TCP options (useful to ignore MSS on captures with TSO)")
)

var stats struct {
	ipdefrag            int
	missedBytes         int
	pkt                 int
	sz                  int
	totalsz             int
	rejectFsm           int
	rejectOpt           int
	rejectConnFsm       int
	reassembled         int
	outOfOrderBytes     int
	outOfOrderPackets   int
	biggestChunkBytes   int
	biggestChunkPackets int
	overlapBytes        int
	overlapPackets      int
}

func writeRequest(req *http.Request, h *httpReader) {
	log.Println("Writing request")

	f, err := os.OpenFile("request.txt", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	log.Printf("File opened: req: %v; ident: %s\n", req, h.ident)

	if _, err = f.WriteString(h.ident + "\n"); err != nil {
		log.Fatal(err)
	}

	if _, err = f.WriteString(req.Method + " " + req.RequestURI + " " + req.Proto + "\n"); err != nil {
		log.Fatal(err)
	}

	for k, v := range req.Header {
		strVal := strings.Join(v, " ")
		if _, err = f.WriteString(k + ": " + strVal + "\n"); err != nil {
			log.Fatal(err)
		}
	}
}

func writeResponse(resp *http.Response, body []byte) {
	log.Println("Writing response")

	f, err := os.OpenFile("response.txt", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	log.Printf("File opened: resp: %v; ident: %s\n", resp, string(body))

	if _, err = f.WriteString(resp.Proto + " " + resp.Status + "\n"); err != nil {
		log.Fatal(err)
	}

	for k, v := range resp.Header {
		strVal := strings.Join(v, " ")
		if _, err = f.WriteString(k + ": " + strVal + "\n"); err != nil {
			log.Fatal(err)
		}
	}

	// appending new line
	if _, err = f.WriteString("\n"); err != nil {
		log.Fatal(err)
	}

	if _, err = f.WriteString(string(body) + "\n"); err != nil {
		log.Fatal(err)
	}
}

type httpReader struct {
	ident    string
	isClient bool
	bytes    chan []byte
	data     []byte
	hexdump  bool
	parent   *tcpStream
}

func (h *httpReader) Read(p []byte) (n int, err error) {
	log.Println("Reading data from reader")
	ok := true
	for ok && len(h.data) == 0 {
		h.data, ok = <-h.bytes
	}
	if !ok || len(h.data) == 0 {
		return 0, io.EOF
	}

	l := copy(p, h.data)
	h.data = h.data[l:]

	log.Println("Reading res: ", l)
	return l, nil
}

func (h *httpReader) run(wg *sync.WaitGroup) {
	defer wg.Done()
	log.Println("running httpReader")

	buf := bufio.NewReader(h)
	for {
		if h.isClient {
			log.Println("client running")

			req, err := http.ReadRequest(buf)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				log.Println("EOF or UnexpectedEOF")
				return
			} else if err != nil {
				log.Printf("HTTP-request: HTTP/%s Request error: %v\n", h.ident, err)
				continue
			}
			log.Println("Request was read")

			writeRequest(req, h)

		} else {
			log.Println("server running")

			resp, err := http.ReadResponse(buf, nil)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				log.Printf("HTTP-response: HTTP/%s Response error: %v\n", h.ident, err)
				continue
			}

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Printf("HTTP-response-body: HTTP/%s - failed to read body, err: %v\n", h.ident, err)
			}

			log.Println("Body was read: ", string(body))

			writeResponse(resp, body)
		}
	}
}

// httpStream will handle the actual decoding of http requests.
type tcpStream struct {
	net, transport gopacket.Flow
	isDNS          bool
	isHTTP         bool
	reversed       bool
	fsmerr         bool
	ident          string
	client         httpReader
	server         httpReader
	tcpstate       *reassembly.TCPSimpleFSM
	optchecker     reassembly.TCPOptionCheck
}

func (t *tcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// FSM
	if !t.tcpstate.CheckState(tcp, dir) {
		log.Printf("FSM %s: Packet rejected by FSM (state:%s)\n", t.ident, t.tcpstate.String())
		stats.rejectFsm++
		if !t.fsmerr {
			t.fsmerr = true
			stats.rejectConnFsm++
		}
		if !*ignorefsmerr {
			return false
		}
	}
	// Options
	err := t.optchecker.Accept(tcp, ci, dir, nextSeq, start)
	if err != nil {
		log.Printf("OptionChecker %s: Packet rejected by OptionChecker: %s\n", t.ident, err)
		stats.rejectOpt++
		if !*nooptcheck {
			return false
		}
	}
	// Checksum
	accept := true
	if *checksum {
		c, err := tcp.ComputeChecksum()
		if err != nil {
			log.Printf("ChecksumCompute %s: Got error computing checksum: %s\n", t.ident, err)
			accept = false
		} else if c != 0x0 {
			log.Printf("Checksum %s: Invalid checksum: 0x%x\n", t.ident, c)
			accept = false
		}
	}
	if !accept {
		stats.rejectOpt++
	}
	return accept
}

func (t *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	log.Println("Start reassemble")

	dir, start, end, skip := sg.Info()
	length, saved := sg.Lengths()
	// update stats
	sgStats := sg.Stats()
	if skip > 0 {
		stats.missedBytes += skip
	}
	stats.sz += length - saved
	stats.pkt += sgStats.Packets
	if sgStats.Chunks > 1 {
		stats.reassembled++
	}
	stats.outOfOrderPackets += sgStats.QueuedPackets
	stats.outOfOrderBytes += sgStats.QueuedBytes
	if length > stats.biggestChunkBytes {
		stats.biggestChunkBytes = length
	}
	if sgStats.Packets > stats.biggestChunkPackets {
		stats.biggestChunkPackets = sgStats.Packets
	}
	if sgStats.OverlapBytes != 0 && sgStats.OverlapPackets == 0 {
		fmt.Printf("bytes:%d, pkts:%d\n", sgStats.OverlapBytes, sgStats.OverlapPackets)
		panic("Invalid overlap")
	}
	stats.overlapBytes += sgStats.OverlapBytes
	stats.overlapPackets += sgStats.OverlapPackets

	var ident string
	if dir == reassembly.TCPDirClientToServer {
		ident = fmt.Sprintf("%v %v(%s): ", t.net, t.transport, dir)
	} else {
		ident = fmt.Sprintf("%v %v(%s): ", t.net.Reverse(), t.transport.Reverse(), dir)
	}
	log.Printf("%s: SG reassembled packet with %d bytes (start:%v,end:%v,skip:%d,saved:%d,nb:%d,%d,overlap:%d,%d)\n", ident, length, start, end, skip, saved, sgStats.Packets, sgStats.Chunks, sgStats.OverlapBytes, sgStats.OverlapPackets)
	if skip == -1 && *allowmissinginit {
		// this is allowed
	} else if skip != 0 {
		// Missing bytes in stream: do not even try to parse it
		return
	}
	data := sg.Fetch(length)
	if t.isDNS {
		dns := &layers.DNS{}
		var decoded []gopacket.LayerType
		if len(data) < 2 {
			if len(data) > 0 {
				sg.KeepFrom(0)
			}
			return
		}
		dnsSize := binary.BigEndian.Uint16(data[:2])
		missing := int(dnsSize) - len(data[2:])
		log.Printf("dnsSize: %d, missing: %d\n", dnsSize, missing)
		if missing > 0 {
			log.Printf("Missing some bytes: %d\n", missing)
			sg.KeepFrom(0)
			return
		}
		p := gopacket.NewDecodingLayerParser(layers.LayerTypeDNS, dns)
		err := p.DecodeLayers(data[2:], &decoded)
		if err != nil {
			log.Printf("DNS-parser Failed to decode DNS: %v\n", err)
		} else {
			log.Printf("DNS: %s\n", gopacket.LayerDump(dns))
		}
		if len(data) > 2+int(dnsSize) {
			sg.KeepFrom(2 + int(dnsSize))
		}
	} else if t.isHTTP {
		if length > 0 {
			if *hexdump {
				log.Printf("Feeding http with:\n%s", hex.Dump(data))
			}
			if dir == reassembly.TCPDirClientToServer && !t.reversed {
				t.client.bytes <- data
			} else {
				t.server.bytes <- data
			}
		}
	}
}

func (t *tcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	log.Printf("%s Reassembly Completed \n", t.ident)
	if t.isHTTP {
		close(t.client.bytes)
		close(t.server.bytes)
	}

	return false
}

/// httpStreamFactory implements reassembly.StreamFactory
type httpStreamFactory struct {
	wg sync.WaitGroup
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, assCtx reassembly.AssemblerContext) reassembly.Stream {
	fsmOptions := reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: *allowmissinginit,
	}

	stream := &tcpStream{
		net:        net,
		transport:  transport,
		isDNS:      tcp.SrcPort == 53 || tcp.DstPort == 53,
		isHTTP:     tcp.SrcPort == 80 || tcp.DstPort == 80,
		reversed:   tcp.SrcPort == 80,
		tcpstate:   reassembly.NewTCPSimpleFSM(fsmOptions),
		ident:      fmt.Sprintf("%s:%s", net, transport),
		optchecker: reassembly.NewTCPOptionCheck(),
	}

	log.Println("Stream set up: ", stream)

	if stream.isHTTP {
		log.Println("stream is indeed http")

		stream.client = httpReader{
			bytes:    make(chan []byte),
			ident:    fmt.Sprintf("%s %s", net, transport),
			hexdump:  *hexdump,
			parent:   stream,
			isClient: true,
		}

		stream.server = httpReader{
			bytes:    make(chan []byte),
			ident:    fmt.Sprintf("%s %s", net.Reverse(), transport.Reverse()),
			hexdump:  *hexdump,
			parent:   stream,
			isClient: false,
		}

		h.wg.Add(2)
		go stream.client.run(&h.wg)
		go stream.server.run(&h.wg)
	}

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return stream
}

type assemblerSimpleContext gopacket.CaptureInfo

func (assCtx *assemblerSimpleContext) GetCaptureInfo() gopacket.CaptureInfo {
	return gopacket.CaptureInfo(*assCtx)
}

func main() {
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal("opening pcap file")
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal(err)
	}
	log.Println("filter set")

	// Set up assembly
	streamFactory := &httpStreamFactory{}
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)

	log.Println("assembly was set up")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	log.Println("Start iteration over packets")
	for packet := range packets {
		tcp, ok := packet.TransportLayer().(*layers.TCP)
		if !ok {
			continue
		}
		assCtx := assemblerSimpleContext(gopacket.CaptureInfo{Timestamp: packet.Metadata().Timestamp})
		stats.totalsz += len(tcp.Payload)
		assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &assCtx)
	}

	log.Println("Waiting goroutines")
	streamFactory.wg.Wait()
	log.Println("Goroutines done")

	fmt.Printf("TCP stats:\n")
	fmt.Printf(" missed bytes:\t\t%d\n", stats.missedBytes)
	fmt.Printf(" total packets:\t\t%d\n", stats.pkt)
	fmt.Printf(" rejected FSM:\t\t%d\n", stats.rejectFsm)
	fmt.Printf(" rejected Options:\t%d\n", stats.rejectOpt)
	fmt.Printf(" reassembled bytes:\t%d\n", stats.sz)
	fmt.Printf(" total TCP bytes:\t%d\n", stats.totalsz)
	fmt.Printf(" conn rejected FSM:\t%d\n", stats.rejectConnFsm)
	fmt.Printf(" reassembled chunks:\t%d\n", stats.reassembled)
	fmt.Printf(" out-of-order packets:\t%d\n", stats.outOfOrderPackets)
	fmt.Printf(" out-of-order bytes:\t%d\n", stats.outOfOrderBytes)
	fmt.Printf(" biggest-chunk packets:\t%d\n", stats.biggestChunkPackets)
	fmt.Printf(" biggest-chunk bytes:\t%d\n", stats.biggestChunkBytes)
	fmt.Printf(" overlap packets:\t%d\n", stats.overlapPackets)
	fmt.Printf(" overlap bytes:\t\t%d\n", stats.overlapBytes)
}