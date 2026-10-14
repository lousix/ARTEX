package hybrid

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type CodeRef struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Revision  string `json:"revision,omitempty"`
}

func ReadSource(root, path string, start, end int) (string, error) {
	p, err := Resolve(root, path)
	if err != nil {
		return "", err
	}
	if start < 1 {
		start = 1
	}
	if end < start {
		end = start + 99
	}
	if end-start >= 300 {
		return "", errors.New("一次最多读取 300 行")
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 4<<20 {
		return "", errors.New("只读取 4 MiB 以内的文本文件")
	}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), 128<<10)
	var b strings.Builder
	for line := 1; s.Scan(); line++ {
		if strings.ContainsRune(s.Text(), 0) {
			return "", errors.New("不支持二进制文件")
		}
		if line >= start && line <= end {
			b.WriteString(s.Text())
			b.WriteByte('\n')
		}
		if line >= end || b.Len() > 64<<10 {
			break
		}
	}
	return b.String(), s.Err()
}

type Match struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

// SearchSource uses literal matching, bounded output and no repository execution.
func SearchSource(root, query string) ([]Match, error) {
	return SearchSourceContext(context.Background(), root, query)
}

func SearchSourceContext(ctx context.Context, root, query string) ([]Match, error) {
	if len(query) == 0 || len(query) > 500 {
		return nil, errors.New("query 长度需要为 1–500")
	}
	var matches []Match
	files := 0
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if p != root {
				switch d.Name() {
				case ".git", "node_modules", "vendor", ".next", "dist":
					return filepath.SkipDir
				}
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		files++
		if files > 10000 || len(matches) >= 100 {
			return io.EOF
		}
		fi, err := d.Info()
		if err != nil || !fi.Mode().IsRegular() || fi.Size() > 1<<20 {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 4096), 64<<10)
		for line := 1; s.Scan(); line++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			v := s.Text()
			if strings.ContainsRune(v, 0) {
				break
			}
			if strings.Contains(v, query) {
				rel, _ := filepath.Rel(root, p)
				if len(v) > 1000 {
					v = v[:1000]
				}
				matches = append(matches, Match{filepath.ToSlash(rel), line, v})
			}
			if len(matches) >= 100 {
				return io.EOF
			}
		}
		return nil
	})
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return matches, err
}
