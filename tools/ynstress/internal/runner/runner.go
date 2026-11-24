package runner

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"

	"yanas/ynstress/internal/scenario"
)

type Result struct {
	Name     string
	OK       bool
	Duration time.Duration
	Output   string
}

func Run(exe string, job scenario.Job, repeat int, timeout time.Duration) Result {
	start := time.Now()
	var last string
	for i := 0; i < repeat; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		cmd := exec.CommandContext(ctx, exe, "-q", job.Path)
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		err := cmd.Run()
		cancel()
		out := buf.String()
		ok := err == nil && !strings.Contains(out, "fatal:")
		if job.Want != "" {
			want := strings.ReplaceAll(job.Want, "\r\n", "\n")
			norm := strings.ReplaceAll(out, "\r\n", "\n")
			ok = ok && strings.Contains(norm, want)
		}
		if !ok {
			return Result{Name: job.Name, OK: false, Duration: time.Since(start), Output: out}
		}
		last = out
	}
	_ = last
	return Result{Name: job.Name, OK: true, Duration: time.Since(start)}
}

func RunAll(exe string, jobs []scenario.Job, repeat, workers int, timeout time.Duration,
	onResult func(Result)) int {
	if workers < 1 {
		workers = 1
	}
	work := make(chan scenario.Job)
	results := make(chan Result)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range work {
				results <- Run(exe, j, repeat, timeout)
			}
		}()
	}

	go func() {
		for _, j := range jobs {
			work <- j
		}
		close(work)
		wg.Wait()
		close(results)
	}()

	fail := 0
	for r := range results {
		if !r.OK {
			fail++
		}
		if onResult != nil {
			onResult(r)
		}
	}
	return fail
}
