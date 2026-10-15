package hybrid

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	MaxArchiveBytes    int64 = 128 << 20
	maxSourceBytes     int64 = 512 << 20
	maxSourceFileBytes int64 = 32 << 20
	maxSourceEntries         = 50000
)

type SourceArchive struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Files  int    `json:"files"`
	Bytes  int64  `json:"bytes"`
	Root   string `json:"root,omitempty"`
}

func archivePath(name string) (string, error) {
	name = strings.ReplaceAll(name, "\\", "/")
	if name == "" || len(name) > 4096 || !utf8.ValidString(name) || strings.ContainsRune(name, 0) || path.IsAbs(name) || strings.Contains(strings.Split(name, "/")[0], ":") {
		return "", errors.New("代码包含非法文件路径")
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", errors.New("代码包不允许包含 .. 路径")
		}
	}
	clean := path.Clean(name)
	return clean, nil
}

type sourceReader struct {
	ctx context.Context
	io.Reader
}

func (r sourceReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

// ExtractSource only writes regular files into a newly allocated directory.
// The caller owns removal of that directory if extraction fails.
func ExtractSource(ctx context.Context, input io.ReaderAt, size int64, dest string) (SourceArchive, error) {
	var info SourceArchive
	if size <= 0 || size > MaxArchiveBytes {
		return info, errors.New("代码 ZIP 包不能超过 128 MiB")
	}
	zr, err := zip.NewReader(input, size)
	if err != nil {
		return info, errors.New("无法读取 ZIP，请上传完整的 ZIP 代码包")
	}
	if len(zr.File) > maxSourceEntries {
		return info, errors.New("代码包条目超过 50000 个")
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, sourceReader{ctx, io.NewSectionReader(input, 0, size)}); err != nil {
		return info, err
	}
	info.SHA256 = hex.EncodeToString(hash.Sum(nil))
	seen := map[string]bool{}
	var declared uint64
	for _, f := range zr.File {
		if err = ctx.Err(); err != nil {
			return info, err
		}
		name, err := archivePath(f.Name)
		if err != nil {
			return info, err
		}
		if name == "." {
			if f.FileInfo().IsDir() {
				continue
			}
			return info, errors.New("代码包含空文件路径")
		}
		if f.Mode()&os.ModeSymlink != 0 || (!f.FileInfo().IsDir() && !f.Mode().IsRegular()) {
			return info, errors.New("代码包不支持软链接或特殊文件，请打包实际源码文件")
		}
		if strings.Split(name, "/")[0] == "__MACOSX" || path.Base(name) == ".DS_Store" {
			continue
		}
		if f.UncompressedSize64 > uint64(maxSourceFileBytes) {
			return info, fmt.Errorf("文件 %s 超过 32 MiB", name)
		}
		declared += f.UncompressedSize64
		if declared > uint64(maxSourceBytes) {
			return info, errors.New("代码包解压后不能超过 512 MiB")
		}
		key := strings.ToLower(name)
		if seen[key] {
			return info, fmt.Errorf("代码包存在重名路径：%s", name)
		}
		seen[key] = true
		dst := filepath.Join(dest, filepath.FromSlash(name))
		if f.FileInfo().IsDir() {
			if err = os.MkdirAll(dst, 0700); err != nil {
				return info, errors.New("无法创建源码目录")
			}
			continue
		}
		if err = os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			return info, errors.New("代码包文件与目录冲突")
		}
		if err = extractSourceFile(ctx, f, dst, &info); err != nil {
			return info, err
		}
	}
	if info.Files == 0 {
		return info, errors.New("代码包没有可审计文件")
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		return info, err
	}
	if len(entries) == 1 && entries[0].IsDir() {
		info.Root = entries[0].Name()
	}
	return info, nil
}

func extractSourceFile(ctx context.Context, f *zip.File, dst string, info *SourceArchive) error {
	r, err := f.Open()
	if err != nil {
		return errors.New("代码包文件损坏")
	}
	defer r.Close()
	w, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("无法写入源码文件或路径冲突")
	}
	n, copyErr := io.Copy(w, io.LimitReader(sourceReader{ctx, r}, maxSourceFileBytes+1))
	closeErr := w.Close()
	if copyErr != nil || closeErr != nil {
		return errors.New("代码包损坏或解压被中断")
	}
	info.Bytes += n
	info.Files++
	if n > maxSourceFileBytes || info.Bytes > maxSourceBytes {
		return errors.New("代码包解压大小超过限制")
	}
	return nil
}
