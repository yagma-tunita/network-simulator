package check

import (
	"fmt"
	"net"

	"yanas/ynpcap/internal/pcap"
	"yanas/ynpcap/internal/proto"
)

type Issue struct {
	Frame int
	Proto string
	Text  string
}

type Stats struct {
	Frames      int
	IPv4        int
	TCPSegments int
	TCPFlows    int
	OSPF        int
	OSPFLSAs    int
	SYNWithMSS  int
	SYNWithWS   int
	SYNWithSACK int
	SYNWithTS   int
	TCPData     int
	TCPRetrans  int
	TCPSACK     int
	TCPECN      int
	TCPCE       int
	TCPDF       int
	Issues      []Issue
}

type flow struct {
	established   bool
	sawSyn        bool
	sawSynAck     bool
	client        string
	clientISN     uint32
	serverISN     uint32
	clientMSS     uint16
	serverMSS     uint16
	haveClientMSS bool
	haveServerMSS bool
	maxCSeq       uint32
	maxSSeq       uint32
}

type Analyzer struct {
	stats   Stats
	flows   map[string]*flow
	OspfKey []byte
}

func New() *Analyzer {
	return &Analyzer{flows: make(map[string]*flow)}
}

func key(ip1 string, p1 uint16, ip2 string, p2 uint16) string {
	return fmt.Sprintf("%s:%d|%s:%d", ip1, p1, ip2, p2)
}

func (a *Analyzer) issue(frame int, name, text string) {
	a.stats.Issues = append(a.stats.Issues, Issue{Frame: frame, Proto: name, Text: text})
}

func (a *Analyzer) Analyze(frame int, data []byte) {
	a.stats.Frames++

	eth, err := proto.ParseEthernet(data)
	if err != nil {
		a.issue(frame, "ethernet", err.Error())
		return
	}
	if eth.EtherType != 0x0800 {
		return
	}

	ip, err := proto.ParseIPv4(eth.Payload)
	if err != nil {
		a.issue(frame, "ipv4", err.Error())
		return
	}
	a.stats.IPv4++
	if !ip.ChecksumOK {
		a.issue(frame, "ipv4", "bad header checksum")
	}

	if ip.Protocol == 6 {
		tcp, err := proto.ParseTCP(ip.Payload, ip.Src, ip.Dst)
		if err != nil {
			a.issue(frame, "tcp", err.Error())
			return
		}
		a.analyzeTCP(frame, ip, tcp)
	} else if ip.Protocol == 89 {
		ospf, err := proto.ParseOSPF(ip.Payload)
		if err != nil {
			a.issue(frame, "ospf", err.Error())
			return
		}
		if ospf.AuthType == 2 && ospf.AuthDataLen == 16 &&
			len(a.OspfKey) == 16 && !proto.VerifyOSPFMD5(ip.Payload, a.OspfKey) {
			a.issue(frame, "ospf", "bad MD5 digest")
		}
		a.analyzeOSPF(frame, ospf)
	}
}

func (a *Analyzer) analyzeTCP(frame int, ip proto.IPv4, tcp proto.TCP) {
	a.stats.TCPSegments++
	if !tcp.ChecksumOK {
		a.issue(frame, "tcp", "bad checksum")
	}

	direct := key(ip.SrcIP(), tcp.SrcPort, ip.DstIP(), tcp.DstPort)
	reverse := key(ip.DstIP(), tcp.DstPort, ip.SrcIP(), tcp.SrcPort)

	f := a.flows[direct]
	if f == nil {
		f = a.flows[reverse]
	}

	if tcp.Flags&proto.TCPSyn != 0 && tcp.Flags&proto.TCPAck == 0 {
		if f == nil {
			f = &flow{client: direct}
			a.flows[direct] = f
			a.stats.TCPFlows++
			if _, ok := tcp.MSS(); ok {
				a.stats.SYNWithMSS++
			}
			if _, ok := tcp.WindowScale(); ok {
				a.stats.SYNWithWS++
			}
			if tcp.SACKPermitted() {
				a.stats.SYNWithSACK++
			}
			if _, _, ok := tcp.Timestamps(); ok {
				a.stats.SYNWithTS++
			}
		}
		f.sawSyn = true
		f.clientISN = tcp.Seq
		if m, ok := tcp.MSS(); ok {
			f.clientMSS = m
			f.haveClientMSS = true
		}
		return
	}

	if tcp.Flags&proto.TCPSyn != 0 && tcp.Flags&proto.TCPAck != 0 {
		if f == nil || !f.sawSyn {
			a.issue(frame, "tcp", "SYN-ACK without observed SYN")
			return
		}
		f.sawSynAck = true
		f.serverISN = tcp.Seq
		if m, ok := tcp.MSS(); ok {
			f.serverMSS = m
			f.haveServerMSS = true
		}
		return
	}

	if f == nil {
		return
	}
	if tcp.Flags&proto.TCPFin != 0 || tcp.Flags&proto.TCPRst != 0 {
		return
	}
	if f.sawSynAck && tcp.Flags&proto.TCPAck != 0 && !f.established {
		f.established = true
	}

	a.stats.TCPSACK += len(tcp.SACKBlocks())
	if ip.ECN != 0 {
		a.stats.TCPECN++
	}
	if ip.ECN == 3 {
		a.stats.TCPCE++
	}
	if ip.DF {
		a.stats.TCPDF++
	}

	if len(tcp.Payload) == 0 {
		return
	}

	a.stats.TCPData++
	fromClient := direct == f.client
	if fromClient {
		if f.haveServerMSS && len(tcp.Payload) > int(f.serverMSS) {
			a.issue(frame, "tcp", "payload exceeds peer MSS")
		}
		if f.maxCSeq != 0 && tcp.Seq <= f.maxCSeq {
			a.stats.TCPRetrans++
		}
		if f.maxCSeq == 0 || tcp.Seq > f.maxCSeq {
			f.maxCSeq = tcp.Seq
		}
	} else {
		if f.haveClientMSS && len(tcp.Payload) > int(f.clientMSS) {
			a.issue(frame, "tcp", "payload exceeds peer MSS")
		}
		if f.maxSSeq != 0 && tcp.Seq <= f.maxSSeq {
			a.stats.TCPRetrans++
		}
		if f.maxSSeq == 0 || tcp.Seq > f.maxSSeq {
			f.maxSSeq = tcp.Seq
		}
	}
}

func (a *Analyzer) analyzeOSPF(frame int, ospf proto.OSPF) {
	a.stats.OSPF++
	if ospf.Version != 2 {
		a.issue(frame, "ospf", "version is not 2")
	}
	if ospf.Type < 1 || ospf.Type > 5 {
		a.issue(frame, "ospf", fmt.Sprintf("unknown packet type %d", ospf.Type))
	}
	if ospf.AuthType != 0 && ospf.AuthType != 1 && ospf.AuthType != 2 {
		a.issue(frame, "ospf", fmt.Sprintf("unsupported auth type %d", ospf.AuthType))
	}
	if !ospf.ChecksumOK {
		a.issue(frame, "ospf", "bad packet checksum")
	}
	a.stats.OSPFLSAs += len(ospf.LSAs)
	for _, l := range ospf.LSAs {
		if !l.ChecksumOK {
			a.issue(frame, "ospf", fmt.Sprintf("bad LSA checksum id=%s",
				net.IP(l.ID[:]).String()))
		}
	}
}

func (a *Analyzer) Finish() Stats {
	return a.stats
}

func (a *Analyzer) AnalyzeRecord(frame int, rec pcap.Record) {
	a.Analyze(frame, rec.Data)
}
