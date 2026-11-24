package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"yanas/ynpcap/internal/check"
	"yanas/ynpcap/internal/pcap"
)

func main() {
	quiet := flag.Bool("q", false, "only print the summary and issues")
	ospfKey := flag.String("ospf-key", "", "16-byte OSPF MD5 key for digest verification")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [-q] [-ospf-key key] capture.pcap\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if *ospfKey != "" && len(*ospfKey) != 16 {
		fmt.Fprintln(os.Stderr, "ospf-key must be exactly 16 bytes")
		os.Exit(2)
	}

	f, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer f.Close()

	r, err := pcap.NewReader(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	a := check.New()
	if *ospfKey != "" {
		a.OspfKey = []byte(*ospfKey)
	}
	frames := 0
	for {
		rec, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "pcap: %v\n", err)
			os.Exit(2)
		}
		frames++
		a.Analyze(frames, rec.Data)
	}

	st := a.Finish()
	if !*quiet {
		fmt.Printf("frames=%d ipv4=%d tcp_segments=%d tcp_flows=%d ospf=%d ospf_lsas=%d\n",
			st.Frames, st.IPv4, st.TCPSegments, st.TCPFlows, st.OSPF, st.OSPFLSAs)
		fmt.Printf("syn_options: mss=%d ws=%d sack=%d ts=%d\n",
			st.SYNWithMSS, st.SYNWithWS, st.SYNWithSACK, st.SYNWithTS)
	}
	for _, is := range st.Issues {
		fmt.Printf("frame %d %s: %s\n", is.Frame, is.Proto, is.Text)
	}
	fmt.Printf("ynpcap: frames=%d issues=%d\n", st.Frames, len(st.Issues))
	if len(st.Issues) != 0 {
		os.Exit(1)
	}
}
