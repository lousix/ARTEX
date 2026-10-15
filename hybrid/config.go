// Package hybrid provides task-local source access and authenticated HTTP sessions.
package hybrid

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Profile struct {
	Name         string `json:"name"`
	ScriptPath   string `json:"script_path"`
	IdentityPath string `json:"identity_path"`
	SubjectField string `json:"subject_field,omitempty"` // dotted JSON path; default id
}

// Config contains no credentials. Scripts receive credentials from the operator's
// environment; session material remains in the server's memory.
type Config struct {
	Mode          string         `json:"mode"`
	SourcePath    string         `json:"source_path,omitempty"`
	SourceArchive *SourceArchive `json:"source_archive,omitempty"`
	Revision      string         `json:"revision,omitempty"`
	BaseURL       string         `json:"base_url,omitempty"`
	Profiles      []Profile      `json:"profiles,omitempty"`
}

// Resolve follows symlinks and then enforces containment, including nested links.
func Resolve(root, rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) {
		return "", errors.New("需要工作空间相对路径")
	}
	base, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	base, err = filepath.Abs(base)
	if err != nil {
		return "", err
	}
	p, err := filepath.EvalSymlinks(filepath.Join(base, rel))
	if err != nil {
		return "", err
	}
	r, err := filepath.Rel(base, p)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", errors.New("路径超出工作空间")
	}
	return p, nil
}

func (c Config) Validate(root string) error {
	if c.Mode != "blackbox" && c.Mode != "hybrid" && c.Mode != "code_audit" {
		return errors.New("mode 必须为 blackbox / hybrid / code_audit")
	}
	if c.Mode != "blackbox" && c.SourcePath == "" {
		return errors.New("代码审计需要项目源码，请上传 ZIP 代码包")
	}
	if c.SourcePath != "" {
		p, err := Resolve(root, c.SourcePath)
		if err != nil {
			return fmt.Errorf("source_path: %w", err)
		}
		fi, err := os.Stat(p)
		if err != nil || !fi.IsDir() {
			return errors.New("source_path 必须为目录")
		}
	}
	if len(c.Profiles) > 8 {
		return errors.New("最多 8 个登录身份")
	}
	if c.Mode == "code_audit" && len(c.Profiles) > 0 {
		return errors.New("纯代码审计不执行登录脚本，请选择 hybrid")
	}
	if c.BaseURL != "" {
		if _, err := ParseBase(c.BaseURL); err != nil {
			return err
		}
	}
	if len(c.Profiles) > 0 && c.BaseURL == "" {
		return errors.New("登录身份需要 base_url")
	}
	seen := map[string]bool{}
	for _, p := range c.Profiles {
		if p.Name == "" || p.Name == "anonymous" || seen[p.Name] {
			return errors.New("身份名称不能为空、重复或使用 anonymous")
		}
		seen[p.Name] = true
		path, err := Resolve(root, p.ScriptPath)
		if err != nil {
			return fmt.Errorf("登录脚本: %w", err)
		}
		fi, err := os.Stat(path)
		if err != nil || !fi.Mode().IsRegular() || filepath.Ext(path) != ".py" {
			return errors.New("登录脚本必须为 Python .py 文件")
		}
		u, err := url.Parse(p.IdentityPath)
		if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(p.IdentityPath, "/") {
			return errors.New("identity_path 必须为同站身份检查路径，例如 /api/me")
		}
	}
	return nil
}

func ParseBase(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("base_url 必须为无凭据的 HTTP(S) 地址")
	}
	return u, nil
}

func Target(base *url.URL, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("无效请求地址")
	}
	u = base.ResolveReference(u)
	if u.Scheme != base.Scheme || !strings.EqualFold(u.Host, base.Host) || u.User != nil || u.Fragment != "" {
		return nil, errors.New("请求和重定向只能访问 base_url 的同一 origin")
	}
	return u, nil
}
