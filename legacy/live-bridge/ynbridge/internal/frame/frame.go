package frame

import (
	"encoding/binary"
	"errors"
	"io"
)

const MaxFrame = 65535

func Read(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if n == 0 || n > MaxFrame {
		return nil, errors.New("invalid frame length")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func Write(w io.Writer, data []byte) error {
	if len(data) == 0 || len(data) > MaxFrame {
		return errors.New("invalid frame length")
	}
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}
