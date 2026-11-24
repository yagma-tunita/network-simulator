package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"yanas/ynbridge/internal/bridge"
	"yanas/ynbridge/internal/netsim"
	"yanas/ynbridge/internal/tap"
)

func setup(tapName, addr, route string) error {
	cmds := [][]string{
		{"ip", "link", "set", tapName, "up"},
	}
	if addr != "" {
		cmds = append(cmds, []string{"ip", "addr", "add", addr, "dev", tapName})
	}
	if route != "" {
		cmds = append(cmds, []string{"ip", "route", "add", route, "dev", tapName})
	}
	for _, c := range cmds {
		cmd := exec.Command(c[0], c[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", c[0], err)
		}
	}
	return nil
}

func main() {
	exe := flag.String("exe", "./netsim", "path to the simulator binary")
	scene := flag.String("scene", "", "scene file to load")
	dev := flag.String("dev", "", "simulated port to bridge, e.g. PC1:0")
	tapName := flag.String("tap", "tap0", "TAP interface name")
	scale := flag.Int("scale", 1, "wall-clock milliseconds per logical tick")
	addr := flag.String("addr", "", "optional address to assign to the TAP (CIDR)")
	route := flag.String("route", "", "optional route to add via the TAP")
	loss := flag.Float64("loss", 0, "frame loss percent")
	dup := flag.Float64("dup", 0, "frame duplication percent")
	seed := flag.Int64("seed", 1, "impairment PRNG seed")
	flag.Parse()

	if *scene == "" || *dev == "" {
		flag.Usage()
		os.Exit(2)
	}

	tapDev, err := tap.Open(*tapName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer tapDev.Close()

	if err := setup(*tapName, *addr, *route); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	live, err := netsim.Start(*exe, *scene, *dev, *scale)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer live.Close()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigc
		live.Close()
		tapDev.Close()
		os.Exit(0)
	}()

	if err := bridge.PumpWithOptions(tapDev, live, bridge.Options{
		LossPct: *loss,
		DupPct:  *dup,
		Seed:    *seed,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
