package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/hybrid"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

func TestHybridAssessmentWorkflow(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("postgres not configured")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	root := t.TempDir()
	if err = os.Mkdir(filepath.Join(root, "src"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "src", "handler.go"), []byte("func Order(id string) {\n    repo.FindByID(id)\n}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &hybrid.Config{Mode: "hybrid", SourcePath: "src", Revision: "test-revision", BaseURL: "https://test.example"}
	pt, err := pg.CreateTaskWithOptions("hybrid-test", "验证订单对象授权", db.TaskCreateOptions{Assessment: cfg})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pg.Exec(`DELETE FROM findings WHERE task_id=$1`, pt.ID)
		_, _ = pg.Exec(`DELETE FROM tasks WHERE id=$1`, pt.ID)
		_, _ = pg.Exec(`DELETE FROM explorations WHERE id=$1`, pt.ExplorationID)
	}()
	task := taskFromPG(pt, pg.Exploration(pt.ExplorationID), nil)
	s := &Server{ctx: context.Background(), authSessions: hybrid.NewSessions(), m: &Manager{pg: pg, dir: root, tasks: map[string]*Task{task.ID: task}}}
	oldAugment, oldResolve := agent.ToolAugment, agent.ToolResolve
	defer func() { agent.ToolAugment, agent.ToolResolve = oldAugment, oldResolve }()
	agent.ToolAugment = func(ctx context.Context, key string) ([]actool.CoreTool, agent.DeferredInfo, func()) {
		return s.assessmentTools(ctx, key), agent.DeferredInfo{}, nil
	}
	agent.ToolResolve = nil
	ts := agent.NewToolSet(task.Store, "planner")
	ts.SetTaskID(pt.ID)
	call := func(tools []actool.CoreTool, name, input string) actool.Result {
		t.Helper()
		for _, tool := range tools {
			if tool.Name() == name {
				r, err := tool.Call(context.Background(), json.RawMessage(input), nil)
				if err != nil || r.IsError {
					t.Fatalf("%s: %+v %v", name, r, err)
				}
				return r
			}
		}
		t.Fatalf("missing tool %s", name)
		return actool.Result{}
	}
	call(ts.PlannerTools(), "add_intent", `{"summary":"审计订单读取权限","lane":"code"}`)
	intents, _ := task.Store.ListByKind(db.KindIntent, 10)
	if len(intents) != 1 {
		t.Fatal("code intent missing")
	}
	intent := intents[0]
	var turn int
	provider := retestProvider{complete: func(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		// Assert the actual SDK request, not merely the helper's tool list.
		raw, _ := json.Marshal(req)
		text := string(raw)
		for _, name := range []string{`"name":"Bash"`, `"name":"WebFetch"`, `"name":"report_finding"`, `"name":"http_request_as"`} {
			if strings.Contains(text, name) {
				t.Errorf("code lane exposed %s", name)
			}
		}
		turn++
		if turn == 1 {
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "read", Name: "code_read", Input: json.RawMessage(`{"path":"handler.go","start_line":1,"end_line":3}`)}}}, "tool_use", llm.Usage{}, nil
		}
		if turn == 2 {
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "hypothesis", Name: "record_code_hypothesis", Input: json.RawMessage(`{"summary":"订单读取缺少所有权校验的候选","vulnclass":"IDOR","route":"GET /api/orders/:id","trace":"Order → FindByID","validation_plan":"A 自有订单正常对照，B 访问 A 的测试订单，核查响应所有者","code_refs":[{"path":"handler.go","start_line":1,"end_line":3}]}`)}}}, "tool_use", llm.Usage{}, nil
		}
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockText, Text: "源码候选已写回，等待动态验证。"}}}, "end_turn", llm.Usage{}, nil
	}}
	w := agent.NewWorker(provider, "test", root, nil, 10000, 5)
	w.SetNonStreaming(func() bool { return true })
	_, _, err = w.Execute(context.Background(), "test-worker", pt.ID, nil, task.Store, intent, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	facts, _ := task.Store.ListByKind(db.KindFact, 10)
	var fact *db.Node
	for _, f := range facts {
		var p map[string]any
		_ = json.Unmarshal(f.Payload, &p)
		if p["fact_type"] == "code_hypothesis" {
			fact = f
			if p["confidence"] != "inferred" {
				t.Fatal("candidate confirmed")
			}
			if !strings.Contains(string(f.Payload), "test-revision") {
				t.Fatal("revision missing")
			}
		}
	}
	if fact == nil {
		t.Fatal("code candidate not persisted")
	}
	call(ts.PlannerTools(), "add_intent", fmt.Sprintf(`{"summary":"验证订单横向越权","lane":"authz_verify","parent_ids":[%d]}`, fact.ID))
	intents, _ = task.Store.ListByKind(db.KindIntent, 10)
	var verifier *db.Node
	for _, i := range intents {
		if strings.Contains(string(i.Payload), "authz_verify") {
			verifier = i
		}
	}
	if verifier == nil {
		t.Fatal("verification intent missing")
	}
	workerTools := agent.NewToolSet(task.Store, "verifier")
	workerTools.SetTaskID(pt.ID)
	call(workerTools.WorkerTools(), "report_finding", fmt.Sprintf(`{"summary":"测试确认越权（本测试用合成证据）","vulnclass":"IDOR","severity":"high","intent_id":%d,"evidence":"测试身份和 HTTP 对照","code_fact_ids":[%d]}`, verifier.ID, fact.ID))
	var evidence string
	if err = pg.QueryRow(`SELECT evidence FROM findings WHERE task_id=$1`, pt.ID).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(evidence, "repo.FindByID") || !strings.Contains(evidence, "test-revision") {
		t.Fatal("finding lost code evidence")
	}
	loaded, err := task.Store.Assessment()
	if err != nil || loaded.SourcePath != "src" {
		t.Fatal("assessment did not round trip")
	}
	// Auth context belongs to this task, never a caller-supplied task id.
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: pt.ID, ExplorationID: pt.ExplorationID, IntentID: verifier.ID, Lane: "authz_verify"})
	tools := s.assessmentTools(ctx, "worker")
	hasHTTP := false
	for _, tool := range tools {
		if tool.Name() == "http_request_as" {
			hasHTTP = true
		}
	}
	if !hasHTTP {
		t.Fatal("verification lane missing authenticated requests")
	}
	_, _ = pg.Exec(`DELETE FROM findings WHERE task_id=$1`, pt.ID)
	// code_audit mode refuses a dynamic intent at the domain-tool boundary.
	_, err = pg.Exec(`UPDATE exploration_nodes SET payload=jsonb_set(payload,'{assessment,mode}','"code_audit"') WHERE exploration_id=$1 AND state='origin'`, pt.ExplorationID)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range ts.PlannerTools() {
		if tool.Name() == "add_intent" {
			r, _ := tool.Call(context.Background(), json.RawMessage(`{"summary":"不应执行","lane":"dynamic"}`), nil)
			if !r.IsError {
				t.Fatal("audit-only accepted dynamic intent")
			}
		}
	}
	for _, tool := range s.assessmentTools(ctx, "worker") {
		if tool.Name() == "http_request_as" {
			t.Fatal("audit-only exposed auth tools")
		}
	}
}
