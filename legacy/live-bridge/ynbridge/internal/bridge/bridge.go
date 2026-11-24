package bridge

import (
	"io"
	"math/rand"
	"sync"
)

type FrameConn interface {
	Send([]byte) error
	Receive() ([]byte, error)
}

type Options struct {
	LossPct float64
	DupPct  float64
	Seed    int64
}

type impair struct {
	loss float64
	dup  float64
	rng  *rand.Rand
	mu   sync.Mutex
}

func newImpair(o Options, seed int64) *impair {
	return &impair{
		loss: o.LossPct,
		dup:  o.DupPct,
		rng:  rand.New(rand.NewSource(seed)),
	}
}

func (i *impair) next() float64 {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.rng.Float64() * 100.0
}

func (i *impair) dropped() bool {
	return i.loss > 0 && i.next() < i.loss
}

func (i *impair) duplicated() bool {
	return i.dup > 0 && i.next() < i.dup
}

func Pump(tap io.ReadWriter, conn FrameConn) error {
	return PumpWithOptions(tap, conn, Options{})
}

func PumpWithOptions(tap io.ReadWriter, conn FrameConn, opt Options) error {
	errc := make(chan error, 2)
	up := newImpair(opt, opt.Seed)
	down := newImpair(opt, opt.Seed^0x5eed)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := tap.Read(buf)
			if err != nil {
				errc <- err
				return
			}
			if n == 0 {
				continue
			}
			frame := append([]byte(nil), buf[:n]...)
			if up.dropped() {
				continue
			}
			if err := conn.Send(frame); err != nil {
				errc <- err
				return
			}
			if up.duplicated() {
				_ = conn.Send(frame)
			}
		}
	}()

	go func() {
		for {
			frame, err := conn.Receive()
			if err != nil {
				errc <- err
				return
			}
			if down.dropped() {
				continue
			}
			if _, err := tap.Write(frame); err != nil {
				errc <- err
				return
			}
			if down.duplicated() {
				_, _ = tap.Write(frame)
			}
		}
	}()

	return <-errc
}
