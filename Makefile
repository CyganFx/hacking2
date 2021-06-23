tidy:
	go mod tidy
	go mod vendor

bench-bad:
	go test -gcflags "-m -m" -run none -bench=. ./read_pcap_reassembly/range_packets -benchtime 3s -benchmem -memprofile m.out  -cpuprofile c.out -memprofilerate=1

bench-good:
	go test -gcflags "-m -m" -run none -bench=. ./read_pcap_reassembly/zerocopyReadPacketData -benchtime 3s -benchmem -memprofile m.out  -cpuprofile c.out -memprofilerate=1

pprof-mem:
	go tool pprof read_pcap_reassembly.test -alloc_space m.out

pprof-cpu:
	go tool pprof read_pcap_reassembly.test c.out