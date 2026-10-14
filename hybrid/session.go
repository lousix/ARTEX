package hybrid

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Identity struct {
	Subject string `json:"subject"`
	Role    string `json:"role,omitempty"`
}
type LoginOutput struct {
	Cookies   []*http.Cookie    `json:"cookies"`
	Headers   map[string]string `json:"headers"`
	Identity  Identity          `json:"identity"`
	ExpiresAt time.Time         `json:"expires_at"`
}
type Request struct {
	Profile string            `json:"profile"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

type policyKey struct{}

func WithURLPolicy(ctx context.Context, check func(*url.URL) error) context.Context {
	return context.WithValue(ctx, policyKey{}, check)
}
func checkURL(ctx context.Context, u *url.URL) error {
	if fn, ok := ctx.Value(policyKey{}).(func(*url.URL) error); ok {
		return fn(u)
	}
	return nil
}

type Response struct {
	Profile    string   `json:"profile"`
	Identity   Identity `json:"identity"`
	Version    uint64   `json:"session_version"`
	RequestID  string   `json:"request_id"`
	Status     int      `json:"status"`
	Body       string   `json:"body"`
	BodySHA256 string   `json:"body_sha256"`
	Truncated  bool     `json:"truncated"`
}
type session struct {
	mu      sync.Mutex
	output  LoginOutput
	jar     http.CookieJar
	version uint64
}
type Sessions struct {
	mu       sync.Mutex
	sessions map[string]*session
	loginEnv []string
}

// Reserved login secrets are captured before agent sessions start, then removed
// from the process environment so SDK Bash/MCP children do not inherit them.
func NewSessions() *Sessions {
	m := &Sessions{sessions: map[string]*session{}}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "ARTEX_LOGIN_SECRET_") {
			m.loginEnv = append(m.loginEnv, entry)
			_ = os.Unsetenv(key)
		}
	}
	return m
}

type loginEnvKey struct{}

func (m *Sessions) get(taskID int64, profile string) *session {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := fmt.Sprintf("%d:%s", taskID, profile)
	s := m.sessions[k]
	if s == nil {
		s = &session{}
		m.sessions[k] = s
	}
	return s
}
func (m *Sessions) Forget(taskID int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.sessions {
		if strings.HasPrefix(k, fmt.Sprintf("%d:", taskID)) {
			delete(m.sessions, k)
		}
	}
}

type cappedOutput struct {
	b        bytes.Buffer
	overflow bool
}

func (b *cappedOutput) Write(p []byte) (int, error) {
	n := len(p)
	left := (64 << 10) - b.b.Len()
	if len(p) > left {
		p = p[:left]
		b.overflow = true
	}
	_, _ = b.b.Write(p)
	return n, nil
}

func RunLogin(ctx context.Context, root string, base *url.URL, p Profile) (LoginOutput, error) {
	var out LoginOutput
	script, err := Resolve(root, p.ScriptPath)
	if err != nil {
		return out, errors.New("登录脚本不可读")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", script)
	cmd.Dir = root
	// Only the explicitly installed server environment is inherited. The script is
	// operator-supplied executable code, not code taken from the audited repository.
	cmd.Env = append(os.Environ(), "ARTEX_AUTH_PROFILE="+p.Name, "ARTEX_TARGET_BASE_URL="+base.String())
	if secrets, ok := ctx.Value(loginEnvKey{}).([]string); ok {
		cmd.Env = append(cmd.Env, secrets...)
	}
	var stdout cappedOutput
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	if cmd.Run() != nil {
		return out, errors.New("登录脚本执行失败或超时；脚本输出已隐藏")
	}
	if stdout.overflow || json.Unmarshal(stdout.b.Bytes(), &out) != nil {
		return out, errors.New("登录脚本须输出不超过 64 KiB 的 JSON")
	}
	if out.Identity.Subject == "" {
		return out, errors.New("登录脚本缺少 identity.subject")
	}
	if len(out.Cookies) == 0 && len(out.Headers) == 0 {
		return out, errors.New("登录脚本没有返回认证材料")
	}
	for _, cookie := range out.Cookies {
		if cookie == nil || cookie.Name == "" {
			return out, errors.New("登录脚本返回无效 Cookie")
		}
	}
	if out.ExpiresAt.IsZero() {
		out.ExpiresAt = time.Now().Add(15 * time.Minute)
	}
	if !out.ExpiresAt.After(time.Now()) {
		return out, errors.New("登录脚本返回的会话已过期")
	}
	for k, v := range out.Headers {
		if forbiddenHeader(k) || strings.ContainsAny(k+v, "\r\n") {
			return out, errors.New("登录脚本返回不允许的请求头")
		}
	}
	return out, nil
}

func forbiddenHeader(k string) bool {
	switch strings.ToLower(k) {
	case "host", "proxy-authorization", "proxy-connection", "connection", "transfer-encoding", "content-length":
		return true
	}
	return false
}
func client(base *url.URL, jar http.CookieJar, proxyAddr, caPath string) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	if proxyAddr != "" {
		u, err := url.Parse(proxyAddr)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(u)
	}
	if caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, errors.New("代理 CA 不可读")
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("代理 CA 无效")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: tr, Jar: jar, Timeout: 20 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("重定向超过 5 次")
		}
		if _, err := Target(base, req.URL.String()); err != nil {
			return err
		}
		return checkURL(req.Context(), req.URL)
	}}, nil
}

func do(ctx context.Context, base *url.URL, s *session, r Request, proxyAddr, caPath string) (Response, error) {
	out := Response{Profile: r.Profile, Identity: s.output.Identity, Version: s.version}
	u, err := Target(base, r.URL)
	if err != nil {
		return out, err
	}
	if err = checkURL(ctx, u); err != nil {
		return out, err
	}
	method := strings.ToUpper(r.Method)
	if method == "" {
		method = "GET"
	}
	if len(r.Body) > 1<<20 {
		return out, errors.New("请求体超过 1 MiB")
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), strings.NewReader(r.Body))
	if err != nil {
		return out, errors.New("请求无效")
	}
	for k, v := range r.Headers {
		if forbiddenHeader(k) || strings.EqualFold(k, "Cookie") || strings.EqualFold(k, "Authorization") || strings.ContainsAny(k+v, "\r\n") {
			return out, errors.New("使用 profile 指定认证身份，请勿覆盖认证或代理请求头")
		}
		req.Header.Set(k, v)
	}
	for k, v := range s.output.Headers {
		req.Header.Set(k, v)
	}
	b := make([]byte, 12)
	if _, err = rand.Read(b); err != nil {
		return out, err
	}
	out.RequestID = hex.EncodeToString(b)
	req.Header.Set("X-Artex-Request-ID", out.RequestID)
	c, err := client(base, s.jar, proxyAddr, caPath)
	if err != nil {
		return out, err
	}
	defer c.CloseIdleConnections()
	resp, err := c.Do(req)
	if err != nil {
		return out, errors.New("HTTP 请求失败（请检查目标、代理或重定向范围）")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return out, errors.New("响应读取失败")
	}
	out.Status = resp.StatusCode
	out.Truncated = len(body) > 1<<20
	if out.Truncated {
		body = body[:1<<20]
	}
	hash := sha256.Sum256(body)
	out.BodySHA256 = hex.EncodeToString(hash[:])
	out.Body = redact(string(body), s.output)
	if s.jar != nil {
		out.Body = redact(out.Body, LoginOutput{Cookies: s.jar.Cookies(u)})
	}
	if len(out.Body) > 32<<10 {
		out.Body = out.Body[:32<<10]
		out.Truncated = true
	}
	return out, nil
}
func redact(text string, out LoginOutput) string {
	for _, c := range out.Cookies {
		if c != nil && c.Value != "" {
			text = strings.ReplaceAll(text, c.Value, "[REDACTED]")
		}
	}
	for _, v := range out.Headers {
		if v != "" {
			text = strings.ReplaceAll(text, v, "[REDACTED]")
			if parts := strings.SplitN(v, " ", 2); len(parts) == 2 && parts[1] != "" {
				text = strings.ReplaceAll(text, parts[1], "[REDACTED]")
			}
		}
	}
	return text
}
func subject(body, field string) string {
	if field == "" {
		field = "id"
	}
	var v any
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	if dec.Decode(&v) != nil {
		return ""
	}
	for _, key := range strings.Split(field, ".") {
		obj, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		v = obj[key]
	}
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	}
	return ""
}

func (m *Sessions) Request(ctx context.Context, taskID int64, root string, cfg Config, r Request, proxyAddr, caPath string, refresh bool) (Response, error) {
	base, err := ParseBase(cfg.BaseURL)
	if err != nil {
		return Response{}, err
	}
	u, targetErr := Target(base, r.URL)
	if targetErr != nil {
		return Response{}, targetErr
	}
	if err = checkURL(ctx, u); err != nil {
		return Response{}, err
	}
	if r.Profile == "anonymous" {
		s := &session{}
		s.jar, _ = cookiejar.New(nil)
		return do(ctx, base, s, r, proxyAddr, caPath)
	}
	var p *Profile
	for i := range cfg.Profiles {
		if cfg.Profiles[i].Name == r.Profile {
			p = &cfg.Profiles[i]
			break
		}
	}
	if p == nil {
		return Response{}, errors.New("未知登录身份")
	}
	s := m.get(taskID, r.Profile)
	s.mu.Lock()
	defer s.mu.Unlock()
	needsLogin := refresh || s.jar == nil || time.Now().Add(30*time.Second).After(s.output.ExpiresAt)
	if !needsLogin {
		probe, err := do(ctx, base, s, Request{Profile: r.Profile, URL: p.IdentityPath}, proxyAddr, caPath)
		if err != nil {
			return Response{}, err
		}
		if probe.Status >= 500 {
			return Response{}, errors.New("身份接口暂时不可用，未执行目标请求")
		}
		if probe.Status != 200 || subject(probe.Body, p.SubjectField) != s.output.Identity.Subject {
			s.jar = nil
			needsLogin = true
		}
	}
	if needsLogin {
		out, err := RunLogin(context.WithValue(ctx, loginEnvKey{}, m.loginEnv), root, base, *p)
		if err != nil {
			return Response{}, err
		}
		s.output = out
		s.jar, _ = cookiejar.New(nil)
		s.version++
		s.jar.SetCookies(base, out.Cookies)
		probe, err := do(ctx, base, s, Request{Profile: r.Profile, URL: p.IdentityPath}, proxyAddr, caPath)
		if err != nil || probe.Status != 200 || subject(probe.Body, p.SubjectField) != out.Identity.Subject {
			s.jar = nil
			s.output = LoginOutput{}
			return Response{}, errors.New("身份检查失败：identity_path 的用户 ID 与登录脚本不一致")
		}
	}
	out, err := do(ctx, base, s, r, proxyAddr, caPath)
	if err == nil && (out.Status == 401 || out.Status == 419) {
		s.jar = nil
	}
	// Mutating requests are never replayed automatically after authentication expiry.
	return out, err
}
