package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"yanas/ynstress/internal/runner"
	"yanas/ynstress/internal/scenario"
)

func main() {
	exe := flag.String("exe", filepath.Join(".", "netsim.exe"), "path to the simulator binary")
	single := flag.String("scenario", "", "single scenario file (default: all tests/*.txt)")
	repeat := flag.Int("repeat", 1, "times to run each scenario")
	jobs := flag.Int("jobs", 4, "parallel scenarios")
	timeout := flag.Duration("timeout", 30*time.Second, "timeout per run")
	flag.Parse()

	var list []scenario.Job
	if *single != "" {
		list = append(list, scenario.FromFile(*single))
	} else {
		var err error
		list, err = scenario.Discover("tests")
		if err != nil || len(list) == 0 {
			fmt.Fprintln(os.Stderr, "no tests/*.txt with .want found")
			os.Exit(2)
		}
	}

	if _, err := os.Stat(*exe); err != nil {
		fmt.Fprintf(os.Stderr, "binary not found: %s\n", *exe)
		os.Exit(2)
	}

	start := time.Now()
	fail := runner.RunAll(*exe, list, *repeat, *jobs, *timeout, func(r runner.Result) {
		status := "PASS"
		if !r.OK {
			status = "FAIL"
		}
		fmt.Printf("%s  %-28s %8s\n", status, r.Name, r.Duration.Round(time.Millisecond))
		if !r.OK && r.Output != "" {
			fmt.Println(r.Output)
		}
	})

	fmt.Printf("ynstress: %d scenarios, %d failed, %d runs each, %s\n",
		len(list), fail, *repeat, time.Since(start).Round(time.Millisecond))
	if fail != 0 {
		os.Exit(1)
	}
}
