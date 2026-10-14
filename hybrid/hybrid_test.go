package hybrid

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestSourceContainment(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "handler.go"), []byte("one\ntwo user_id\nthree\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../secret", "escape/secret", filepath.Join(outside, "secret")} {
		if _, err := ReadSource(root, path, 1, 10); err == nil {
			t.Fatalf("escaped: %s", path)
		}
	}
	text, err := ReadSource(root, "handler.go", 2, 2)
	if err != nil || text != "two user_id\n" {
		t.Fatalf("read %q %v", text, err)
	}
	rows, err := SearchSource(root, "user_id")
	if err != nil || len(rows) != 1 || rows[0].Line != 2 {
		t.Fatalf("search %v %v", rows, err)
	}
	if _, err := ReadSource(root, "handler.go", 1, 1000); err == nil {
		t.Fatal("unbounded read")
	}
}

const loginFixture = `import json, os, urllib.request
profile=os.environ['ARTEX_AUTH_PROFILE']
base=os.environ['ARTEX_TARGET_BASE_URL']
with urllib.request.urlopen(base+'/login?profile='+profile, timeout=5) as r:
    data=json.load(r)
print(json.dumps({'cookies':[{'Name':'sid','Value':data['token'],'Path':'/'}],
 'headers':{'X-CSRF-Token':'csrf-super-secret'},'identity':{'subject':data['id'],'role':'user'}}))
`

func TestSessionsIsolationRefreshAndRedaction(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Fatal("python3 required for integration test")
	}
	var logins atomic.Int64
	var tokenMu sync.Mutex
	tokens := map[string]string{}
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/login" {
			name := r.URL.Query().Get("profile")
			n := logins.Add(1)
			token := fmt.Sprintf("session-secret-%s-%d", name, n)
			tokenMu.Lock()
			tokens[token] = name
			tokenMu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{"token": token, "id": name})
			return
		}
		cookie, err := r.Cookie("sid")
		name := ""
		if err == nil {
			tokenMu.Lock()
			name = tokens[cookie.Value]
			tokenMu.Unlock()
		}
		if name == "" {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		if r.URL.Path == "/expire" {
			tokenMu.Lock()
			delete(tokens, cookie.Value)
			tokenMu.Unlock()
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/me" {
			_ = json.NewEncoder(w).Encode(map[string]string{"id": name})
			return
		}
		if r.Header.Get("X-Artex-Request-ID") == "" || r.Header.Get("X-CSRF-Token") != "csrf-super-secret" {
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": name, "echo_cookie": cookie.Value, "csrf": r.Header.Get("X-CSRF-Token")})
	}))
	defer app.Close()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "login.py"), []byte(loginFixture), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Mode: "hybrid", SourcePath: ".", BaseURL: app.URL, Profiles: []Profile{{Name: "user_a", ScriptPath: "login.py", IdentityPath: "/me"}, {Name: "user_b", ScriptPath: "login.py", IdentityPath: "/me"}}}
	if err := cfg.Validate(root); err != nil {
		t.Fatal(err)
	}
	m := NewSessions()
	ctx := context.Background()
	request := func(profile, path string) Response {
		t.Helper()
		out, err := m.Request(ctx, 1, root, cfg, Request{Profile: profile, URL: path}, "", "", false)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	a := request("user_a", "/orders")
	b := request("user_b", "/orders")
	if a.Identity.Subject == b.Identity.Subject || a.Status != 200 || b.Status != 200 {
		t.Fatalf("identity mismatch: %+v %+v", a, b)
	}
	if strings.Contains(a.Body, "session-secret") || strings.Contains(a.Body, "csrf-super-secret") {
		t.Fatal("secret leaked in body")
	}
	if request("anonymous", "/orders").Status != 401 {
		t.Fatal("anonymous inherited credentials")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := m.Request(ctx, 1, root, cfg, Request{Profile: "user_a", URL: "/orders"}, "", "", false)
			if err != nil || out.Identity.Subject != "user_a" {
				t.Errorf("parallel request: %v", err)
			}
		}()
	}
	wg.Wait()
	if logins.Load() != 2 {
		t.Fatalf("login storm: %d", logins.Load())
	}
	request("user_a", "/expire")
	again := request("user_a", "/orders")
	if again.Version != 2 || logins.Load() != 3 {
		t.Fatal("expired session not refreshed")
	}
	other, err := m.Request(ctx, 2, root, cfg, Request{Profile: "user_a", URL: "/orders"}, "", "", false)
	if err != nil || other.Version != 1 || logins.Load() != 4 {
		t.Fatal("tasks shared session")
	}
	if _, err = m.Request(ctx, 1, root, cfg, Request{Profile: "user_a", URL: "/orders", Headers: map[string]string{"Authorization": "Bearer spoof"}}, "", "", false); err == nil {
		t.Fatal("identity override allowed")
	}
}

func TestRedirectAndScopeGates(t *testing.T) {
	var escaped atomic.Int64
	outside := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { escaped.Add(1) }))
	defer outside.Close()
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, outside.URL, http.StatusFound) }))
	defer app.Close()
	m := NewSessions()
	cfg := Config{Mode: "blackbox", BaseURL: app.URL}
	if _, err := m.Request(context.Background(), 1, t.TempDir(), cfg, Request{Profile: "anonymous", URL: "/redirect"}, "", "", false); err == nil {
		t.Fatal("cross origin redirect allowed")
	}
	if escaped.Load() != 0 {
		t.Fatal("credentials/request reached another origin")
	}
	ctx := WithURLPolicy(context.Background(), func(*url.URL) error { return fmt.Errorf("blocked") })
	if _, err := m.Request(ctx, 1, t.TempDir(), cfg, Request{Profile: "anonymous", URL: "/redirect"}, "", "", false); err == nil || err.Error() != "blocked" {
		t.Fatalf("scope gate: %v", err)
	}
}

func TestLoginErrorsDoNotExposeOutput(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "fail.py")
	if err := os.WriteFile(path, []byte("import sys\nprint('super-secret')\nprint('super-secret',file=sys.stderr)\nsys.exit(1)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	base, _ := ParseBase("https://test.example")
	_, err := RunLogin(context.Background(), root, base, Profile{Name: "user_a", ScriptPath: "fail.py"})
	if err == nil || strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("unsafe error: %v", err)
	}
}

func TestReservedSecretsAndIdentityMismatch(t *testing.T) {
	t.Setenv("ARTEX_LOGIN_SECRET_USER_A_PASSWORD", "isolated-secret")
	m := NewSessions()
	if os.Getenv("ARTEX_LOGIN_SECRET_USER_A_PASSWORD") != "" {
		t.Fatal("SDK children could inherit login secret")
	}
	root := t.TempDir()
	script := `import os,json
secret=os.environ['ARTEX_LOGIN_SECRET_USER_A_PASSWORD']
print(json.dumps({'cookies':[{'Name':'sid','Value':secret,'Path':'/'}],'identity':{'subject':'claimed-user'}}))
`
	if err := os.WriteFile(filepath.Join(root, "login.py"), []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, `{"id":"actual-user"}`) }))
	defer app.Close()
	cfg := Config{Mode: "blackbox", BaseURL: app.URL, Profiles: []Profile{{Name: "user_a", ScriptPath: "login.py", IdentityPath: "/me"}}}
	_, err := m.Request(context.Background(), 1, root, cfg, Request{Profile: "user_a", URL: "/orders"}, "", "", false)
	if err == nil || !strings.Contains(err.Error(), "身份检查失败") || strings.Contains(err.Error(), "isolated-secret") {
		t.Fatalf("bad identity accepted or secret exposed: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatal("resource requested before identity validated")
	}
}
