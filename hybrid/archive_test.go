package hybrid

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sourceZIP(t *testing.T, paths ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, p := range paths {
		f, err := w.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte("package main\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestSourceZIPExtraction(t *testing.T) {
	data := sourceZIP(t, "shop-main/handler.go", "shop-main/internal/auth.go", "__MACOSX/._handler.go")
	dir := t.TempDir()
	info, err := ExtractSource(context.Background(), bytes.NewReader(data), int64(len(data)), dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Root != "shop-main" || info.Files != 2 || len(info.SHA256) != 64 {
		t.Fatalf("bad manifest: %+v", info)
	}
	text, err := ReadSource(filepath.Join(dir, info.Root), "internal/auth.go", 1, 2)
	if err != nil || !strings.Contains(text, "package main") {
		t.Fatalf("extracted source not readable: %s %v", text, err)
	}
	flat := sourceZIP(t, "handler.go", "internal/auth.go")
	info, err = ExtractSource(context.Background(), bytes.NewReader(flat), int64(len(flat)), t.TempDir())
	if err != nil || info.Root != "" {
		t.Fatalf("flat source: %+v %v", info, err)
	}
}

func TestSourceZIPRejectsEscapesAndDuplicates(t *testing.T) {
	for _, p := range []string{"../escape.go", "shop/../../escape.go", "/tmp/escape.go", `C:\source\escape.go`, `shop\..\escape.go`} {
		t.Run(p, func(t *testing.T) {
			data := sourceZIP(t, p)
			if _, err := ExtractSource(context.Background(), bytes.NewReader(data), int64(len(data)), t.TempDir()); err == nil {
				t.Fatal("unsafe path accepted")
			}
		})
	}
	data := sourceZIP(t, "src/a.go", "src/A.go")
	if _, err := ExtractSource(context.Background(), bytes.NewReader(data), int64(len(data)), t.TempDir()); err == nil {
		t.Fatal("case-insensitive duplicate accepted")
	}
}

func TestSourceZIPRejectsLinksAndOversize(t *testing.T) {
	for _, mode := range []os.FileMode{os.ModeSymlink | 0777, os.ModeNamedPipe | 0600} {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		h := &zip.FileHeader{Name: "link"}
		h.SetMode(mode)
		f, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write([]byte("../../private"))
		_ = w.Close()
		if _, err := ExtractSource(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), t.TempDir()); err == nil {
			t.Fatal("special file accepted")
		}
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	_, err := w.CreateRaw(&zip.FileHeader{Name: "huge.bin", Method: zip.Store, UncompressedSize64: uint64(maxSourceFileBytes + 1)})
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if _, err = ExtractSource(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), t.TempDir()); err == nil || !strings.Contains(err.Error(), "32 MiB") {
		t.Fatalf("oversize file accepted: %v", err)
	}
	if _, err = ExtractSource(context.Background(), bytes.NewReader(nil), MaxArchiveBytes+1, t.TempDir()); err == nil {
		t.Fatal("oversize archive accepted")
	}
	if _, err = ExtractSource(context.Background(), bytes.NewReader([]byte("not zip")), 7, t.TempDir()); err == nil {
		t.Fatal("invalid archive accepted")
	}
}

func TestSourceZIPCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	data := sourceZIP(t, "handler.go")
	if _, err := ExtractSource(ctx, bytes.NewReader(data), int64(len(data)), t.TempDir()); err == nil {
		t.Fatal("cancelled extraction continued")
	}
}
