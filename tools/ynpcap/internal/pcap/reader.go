package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	linkEthernet = 1
	maxRecord    = 16 << 20
)

type Record struct {
	TimeNs uint64
	Data   []byte
}

type Reader struct {
	r     io.Reader
	order binary.ByteOrder
	nano  bool
	link  uint32
}

func NewReader(r io.Reader) (*Reader, error) {
	var hdr [24]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}

	var order binary.ByteOrder
	var nano bool
	switch {
	case hdr[0] == 0xd4 && hdr[1] == 0xc3 && hdr[2] == 0xb2 && hdr[3] == 0xa1:
		order = binary.LittleEndian
	case hdr[0] == 0xa1 && hdr[1] == 0xb2 && hdr[2] == 0xc3 && hdr[3] == 0xd4:
		order = binary.BigEndian
	case hdr[0] == 0x4d && hdr[1] == 0x3c && hdr[2] == 0xb2 && hdr[3] == 0xa1:
		order = binary.LittleEndian
		nano = true
	case hdr[0] == 0xa1 && hdr[1] == 0xb2 && hdr[2] == 0x3c && hdr[3] == 0x4d:
		order = binary.BigEndian
		nano = true
	default:
		return nil, errors.New("not a pcap file")
	}

	link := order.Uint32(hdr[20:24])
	if link != linkEthernet {
		return nil, fmt.Errorf("unsupported link type %d", link)
	}
	return &Reader{r: r, order: order, nano: nano, link: link}, nil
}

func (r *Reader) Next() (Record, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(r.r, hdr[:]); err != nil {
		return Record{}, err
	}
	sec := r.order.Uint32(hdr[0:4])
	frac := r.order.Uint32(hdr[4:8])
	incl := r.order.Uint32(hdr[8:12])
	if incl > maxRecord {
		return Record{}, errors.New("pcap record too large")
	}
	data := make([]byte, incl)
	if _, err := io.ReadFull(r.r, data); err != nil {
		return Record{}, err
	}

	ns := uint64(sec) * 1_000_000_000
	if r.nano {
		ns += uint64(frac)
	} else {
		ns += uint64(frac) * 1_000
	}
	return Record{TimeNs: ns, Data: data}, nil
}
