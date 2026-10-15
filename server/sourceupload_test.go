package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/hybrid"
)

func sourceTaskRequest(t *testing.T, req createTaskReq) *http.Request {
	t.Helper()
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	f, err := zw.Create("shop-main/handler.go")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("package main\n"))
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	raw, _ := json.Marshal(req)
	if err = mw.WriteField("task", string(raw)); err != nil {
		t.Fatal(err)
	}
	f, err = mw.CreateFormFile("source", "shop.zip")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write(zipBuf.Bytes())
	if err = mw.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/tasks", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

func TestCreateTaskWithSourceZIP(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("postgres not configured")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Never start an LLM run in this API test.
	m := &Manager{pg: pg, dir: t.TempDir(), tasks: map[string]*Task{}}
	s := &Server{ctx: ctx, m: m, engine: NewEngine(m)}
	request := sourceTaskRequest(t, createTaskReq{Description: "source upload test", Goal: "audit", Assessment: &hybrid.Config{Mode: "code_audit"}})
	w := httptest.NewRecorder()
	s.createTask(w, request)
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	task, ok := m.Task(out.ID)
	if !ok {
		t.Fatal("task not published")
	}
	defer func() {
		s.engine.StopTask(task.ID)
		_, _ = pg.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID)
		_, _ = pg.Exec(`DELETE FROM explorations WHERE id=$1`, task.ExpID)
	}()
	cfg, err := task.Store.Assessment()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SourcePath != "tasks/"+task.ID+"/source/shop-main" || cfg.SourceArchive == nil || cfg.SourceArchive.Name != "shop.zip" {
		t.Fatalf("wrong source config: %+v", cfg)
	}
	ctx = agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: mustTaskNum(t, task.ID), ExplorationID: task.ExpID, Lane: "code"})
	found := false
	for _, tool := range s.assessmentTools(ctx, "worker") {
		if tool.Name() == "code_read" {
			found = true
			r, err := tool.Call(ctx, json.RawMessage(`{"path":"handler.go"}`), nil)
			if err != nil || r.IsError || !strings.Contains(r.Flatten(), "package main") {
				t.Fatalf("source unreadable: %+v %v", r, err)
			}
		}
	}
	if !found {
		t.Fatal("source tools not assembled")
	}
	entries, err := os.ReadDir(filepath.Join(m.dir, ".source-uploads"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("staging not cleaned: %v %v", entries, err)
	}
}

func mustTaskNum(t *testing.T, id string) int64 {
	t.Helper()
	n, err := parseTaskID(id)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSourceUploadValidationCleansStaging(t *testing.T) {
	m := &Manager{dir: t.TempDir(), tasks: map[string]*Task{}}
	s := &Server{m: m}
	w := httptest.NewRecorder()
	s.createTask(w, sourceTaskRequest(t, createTaskReq{SourceTaskIDs: []string{"invalid"}, Assessment: &hybrid.Config{Mode: "code_audit"}}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected validation failure: %d %s", w.Code, w.Body)
	}
	entries, err := os.ReadDir(filepath.Join(m.dir, ".source-uploads"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("validation failure left staging files: %v %v", entries, err)
	}
	if len(m.tasks) != 0 {
		t.Fatal("invalid task published")
	}
}

func TestSourceUploadRollsBackWithTask(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("postgres not configured")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	m := &Manager{pg: pg, dir: t.TempDir(), tasks: map[string]*Task{}}
	s := &Server{m: m}
	var req createTaskReq
	u, err := s.decodeTaskCreation(httptest.NewRecorder(), sourceTaskRequest(t, createTaskReq{Assessment: &hybrid.Config{Mode: "code_audit"}}), &req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.CreateTaskWithOptions("failed source upload", "audit", db.TaskCreateOptions{Assessment: req.Assessment, PrepareAssessment: func(id int64) error {
		if err := u.prepare(id); err != nil {
			return err
		}
		return errors.New("injected transaction failure")
	}})
	if err == nil {
		t.Fatal("injected failure did not rollback")
	}
	u.cleanup()
	if _, err = os.Stat(u.target); !os.IsNotExist(err) {
		t.Fatalf("rolled-back task left source files: %v", err)
	}
	var count int
	if err = pg.QueryRow(`SELECT count(*) FROM tasks WHERE description='failed source upload'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rolled-back task persisted: %d %v", count, err)
	}
}
