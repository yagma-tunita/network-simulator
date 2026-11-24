//go:build linux

package tap

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	tunsetiff = 0x400454ca
	iffTap    = 0x0002
	iffNoPi   = 0x1000
)

type ifreq struct {
	name  [16]byte
	flags uint16
	pad   [22]byte
}

func Open(name string) (*os.File, error) {
	fd, err := syscall.Open("/dev/net/tun", os.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}

	var req ifreq
	copy(req.name[:15], name)
	req.flags = iffTap | iffNoPi
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(tunsetiff), uintptr(unsafe.Pointer(&req))); errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}

	return os.NewFile(uintptr(fd), "/dev/net/tun"), nil
}
