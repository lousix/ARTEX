package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/hybrid"
)

type taskSourceUpload struct {
	workspace      string
	staging        string
	target         string
	taskDir        string
	createdTaskDir bool
	committed      bool
	cfg            *hybrid.Config
}

func (u *taskSourceUpload) cleanup() {
	if u == nil {
		return
	}
	// Both directories are allocated by this request, never supplied by the client.
	if !u.committed {
		if u.target != "" {
			_ = os.RemoveAll(u.target)
		}
		if u.createdTaskDir {
			_ = os.Remove(u.taskDir)
		}
	}
	if u.staging != "" {
		_ = os.RemoveAll(u.staging)
	}
}

func (u *taskSourceUpload) prepare(taskID int64) error {
	u.taskDir = filepath.Join(u.workspace, "tasks", strconv.FormatInt(taskID, 10))
	if _, err := os.Stat(u.taskDir); os.IsNotExist(err) {
		u.createdTaskDir = true
	}
	if err := os.MkdirAll(u.taskDir, 0700); err != nil {
		return err
	}
	target := filepath.Join(u.taskDir, "source")
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		return errors.New("任务源码目录已存在，未覆盖原文件")
	}
	if err := os.Rename(filepath.Join(u.staging, "files"), target); err != nil {
		return fmt.Errorf("保存任务源码失败: %w", err)
	}
	u.target = target
	rel, err := filepath.Rel(u.workspace, filepath.Join(target, u.cfg.SourceArchive.Root))
	if err != nil {
		return err
	}
	u.cfg.SourcePath = filepath.ToSlash(rel)
	return nil
}

// Multipart creation sends metadata and the source archive in one request, so a
// cancelled form does not leave permanent uploads. Legacy JSON creation remains
// supported for API clients and existing task definitions.
func (s *Server) decodeTaskCreation(w http.ResponseWriter, r *http.Request, req *createTaskReq) (*taskSourceUpload, error) {
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType != "multipart/form-data" {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		return nil, json.NewDecoder(r.Body).Decode(req)
	}
	r.Body = http.MaxBytesReader(w, r.Body, hybrid.MaxArchiveBytes+(1<<20))
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
		return nil, errors.New("上传失败：代码包最大 128 MiB，请检查网络和文件大小")
	}
	defer r.MultipartForm.RemoveAll()
	meta := r.FormValue("task")
	if len(meta) > 1<<20 || json.Unmarshal([]byte(meta), req) != nil {
		return nil, errors.New("任务参数格式错误")
	}
	if req.Assessment == nil || (req.Assessment.Mode != "hybrid" && req.Assessment.Mode != "code_audit") {
		return nil, errors.New("上传源码请选择源码审计或混合模式")
	}
	files := r.MultipartForm.File["source"]
	if len(files) != 1 {
		return nil, errors.New("请选择一个 ZIP 代码包")
	}
	header := files[0]
	name := filepath.Base(strings.ReplaceAll(header.Filename, "\\", "/"))
	if !strings.EqualFold(filepath.Ext(name), ".zip") {
		return nil, errors.New("目前支持 ZIP 代码包，请先压缩项目源码")
	}
	file, err := header.Open()
	if err != nil {
		return nil, errors.New("无法读取上传文件")
	}
	defer file.Close()
	stagingRoot := filepath.Join(s.m.dir, ".source-uploads")
	if err = os.MkdirAll(stagingRoot, 0700); err != nil {
		return nil, err
	}
	staging, err := os.MkdirTemp(stagingRoot, "upload-")
	if err != nil {
		return nil, err
	}
	u := &taskSourceUpload{workspace: s.m.dir, staging: staging, cfg: req.Assessment}
	dest := filepath.Join(staging, "files")
	if err = os.Mkdir(dest, 0700); err != nil {
		return u, err
	}
	info, err := hybrid.ExtractSource(r.Context(), file, header.Size, dest)
	if err != nil {
		return u, err
	}
	info.Name = name
	req.Assessment.SourceArchive = &info
	rel, err := filepath.Rel(s.m.dir, filepath.Join(dest, info.Root))
	if err != nil {
		return u, err
	}
	req.Assessment.SourcePath = filepath.ToSlash(rel)
	return u, nil
}
