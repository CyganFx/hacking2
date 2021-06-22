package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

var (
	pcapFile      string = "infocernch.pcap"
	handle        *pcap.Handle
	err           error
	filter        = flag.String("f", "tcp and port 80", "BPF filter for pcap")
	logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")
)

/// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}

	src, _ := transport.Endpoints()
	if fmt.Sprintf("%v", src) == "80" {
		go hstream.runResponse() // Important... we must guarantee that data from the reader stream is read.
	} else {
		go hstream.runRequest() // Important... we must guarantee that data from the reader stream is read.
	}

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *httpStream) runResponse() {

	buf := bufio.NewReader(&h.r)
	defer tcpreader.DiscardBytesToEOF(buf)
	for {
		resp, err := http.ReadResponse(buf, nil)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
			return
		} else {
			bodyBytes, _ := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Fatal(err)
			}

			printResponse(resp, bodyBytes)
			writeResponse(resp, bodyBytes)
		}
	}
}
func (h *httpStream) runRequest() {

	buf := bufio.NewReader(&h.r)
	defer tcpreader.DiscardBytesToEOF(buf)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
		} else {

			printRequest(req, h)
			writeRequest(req, h)
		}
	}
}

func printHeader(h http.Header) {
	for k, v := range h {
		fmt.Println(k, v)
	}
}

func printRequest(req *http.Request, h *httpStream) {
	fmt.Println("----------")
	fmt.Println("This is request:")
	fmt.Println(h.net, h.transport)
	fmt.Println(req.Method, req.RequestURI, req.Proto)
	printHeader(req.Header)
	fmt.Println("----------")
}

func printResponse(resp *http.Response, bodyBytes []byte) {
	fmt.Println("----------")
	fmt.Println("This is response:")
	fmt.Println(resp.Proto, resp.Status)
	printHeader(resp.Header)
	fmt.Println()
	fmt.Println(string(bodyBytes))
	fmt.Println("----------")
}

func writeRequest(req *http.Request, h *httpStream) {
	f, err := os.OpenFile("request.txt", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if _, err = f.WriteString(h.net.String() + " " + h.transport.String() + "\n"); err != nil {
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

func writeResponse(resp *http.Response, bodyBytes []byte) {
	f, err := os.OpenFile("response.txt", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if _, err = f.WriteString(resp.Proto + " " + resp.Status + "\n"); err != nil {
		log.Fatal(err)
	}

	for k, v := range resp.Header {
		strVal := strings.Join(v, " ")
		if _, err = f.WriteString(k + ": " + strVal + "\n"); err != nil {
			log.Fatal(err)
		}
	}

	// just new line
	if _, err = f.WriteString("\n"); err != nil {
		log.Fatal(err)
	}

	if _, err = f.WriteString(string(bodyBytes) + "\n"); err != nil {
		log.Fatal(err)
	}
}

func main() {
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal(err)
	}

	// Set up assembly
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	// Loop through packets in file
	for packet := range packets {
		tcp, ok := packet.TransportLayer().(*layers.TCP)
		if !ok {
			log.Fatal()
		}
		assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().CaptureInfo.Timestamp)
	}
}
