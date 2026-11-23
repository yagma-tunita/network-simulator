package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

type job struct {
	name     string
	scenario string
	want     string
}

type result struct {
	name string
	ok   bool
	dur  time.Duration
	out  string
}

func runOne(exe string, j job, repeat int, timeout time.Duration) result {
	start := time.Now()
	var last string
	for i := 0; i < repeat; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		cmd := exec.CommandContext(ctx, exe, j.scenario)
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		err := cmd.Run()
		cancel()
		out := buf.String()
		ok := err == nil && !bytes.Contains([]byte(out), []byte("fatal:"))
		if j.want != "" {
			ok = ok && bytes.Contains([]byte(out), []byte(j.want))
		}
		if !ok {
			return result{name: j.name, ok: false, dur: time.Since(start), out: out}
		}
		last = out
	}
	_ = last
	return result{name: j.name, ok: true, dur: time.Since(start)}
}

func main() {
	exe := flag.String("exe", filepath.Join(".", "netsim.exe"), "path to the simulator binary")
	scenario := flag.String("scenario", "", "single scenario file (default: all tests/*.txt)")
	repeat := flag.Int("repeat", 1, "times to run each scenario")
	jobs := flag.Int("jobs", 4, "parallel scenarios")
	timeout := flag.Duration("timeout", 30*time.Second, "timeout per run")
	flag.Parse()

	var list []job
	if *scenario != "" {
		wantPath := ""
		if ext := filepath.Ext(*scenario); ext == ".txt" {
			wantPath = (*scenario)[:len(*scenario)-len(ext)] + ".want"
		}
		want := ""
		if wantPath != "" {
			if b, err := os.ReadFile(wantPath); err == nil {
				want = string(bytes.TrimRight(b, "\r\n"))
			}
		}
		list = append(list, job{name: filepath.Base(*scenario), scenario: *scenario, want: want})
	} else {
		files, err := filepath.Glob(filepath.Join("tests", "*.txt"))
		if err != nil || len(files) == 0 {
			fmt.Fprintln(os.Stderr, "no tests/*.txt found")
			os.Exit(2)
		}
		for _, f := range files {
			wantPath := f[:len(f)-len(filepath.Ext(f))] + ".want"
			b, err := os.ReadFile(wantPath)
			if err != nil {
				continue
			}
			list = append(list, job{
				name:     filepath.Base(f),
				scenario: f,
				want:     string(bytes.TrimRight(b, "\r\n")),
			})
		}
	}

	if _, err := os.Stat(*exe); err != nil {
		fmt.Fprintf(os.Stderr, "binary not found: %s\n", *exe)
		os.Exit(2)
	}

	work := make(chan job)
	results := make(chan result)
	var wg sync.WaitGroup

	for i := 0; i < *jobs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range work {
				results <- runOne(*exe, j, *repeat, *timeout)
			}
		}()
	}

	go func() {
		for _, j := range list {
			work <- j
		}
		close(work)
		wg.Wait()
		close(results)
	}()

	fail := 0
	total := time.Now()
	for r := range results {
		status := "PASS"
		if !r.ok {
			status = "FAIL"
			fail++
		}
		fmt.Printf("%s  %-28s %8s\n", status, r.name, r.dur.Round(time.Millisecond))
		if !r.ok && r.out != "" {
			fmt.Println(r.out)
		}
	}

	fmt.Printf("ynstress: %d scenarios, %d failed, %d runs each, %s\n",
		len(list), fail, *repeat, time.Since(total).Round(time.Millisecond))
	if fail != 0 {
		os.Exit(1)
	}
}
