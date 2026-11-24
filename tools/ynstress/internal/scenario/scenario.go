package scenario

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

type Job struct {
	Name string
	Path string
	Want string
}

func FromFile(path string) Job {
	name := filepath.Base(path)
	ext := filepath.Ext(path)
	wantPath := strings.TrimSuffix(path, ext) + ".want"
	want := ""
	if b, err := os.ReadFile(wantPath); err == nil {
		want = string(bytes.TrimRight(b, "\r\n"))
	}
	return Job{Name: name, Path: path, Want: want}
}

func Discover(root string) ([]Job, error) {
	files, err := filepath.Glob(filepath.Join(root, "*.txt"))
	if err != nil {
		return nil, err
	}
	var jobs []Job
	for _, f := range files {
		wantPath := strings.TrimSuffix(f, filepath.Ext(f)) + ".want"
		if _, err := os.Stat(wantPath); err != nil {
			continue
		}
		jobs = append(jobs, FromFile(f))
	}
	return jobs, nil
}
