//go:build !linux

package tap

import (
	"errors"
	"os"
)

func Open(string) (*os.File, error) {
	return nil, errors.New("TAP devices are only supported on Linux")
}
