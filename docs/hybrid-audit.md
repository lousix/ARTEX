# 源码审计与登录身份验证（第一版）

任务创建界面新增「黑盒渗透」「源码审计 + 动态验证」「只读源码审计」。原有任务默认仍为黑盒。

## 启动一个混合任务

1. 在「新建任务」中选择「源码审计 + 动态验证」或「只读源码审计」，点击「选择 ZIP 代码包」上传项目。无需填写项目路径、复制目录到服务器或手动解压；可选填写交付版本/commit SHA。
2. 将 `examples/hybrid/login.py` 复制到工作空间的 `auth/login.py`，按应用修改登录地址、参数和身份字段。脚本是操作员提供的可执行代码，在后端机器上运行，不是容器沙箱。使用可信的脚本。
3. 在启动后端的环境中配置 `ARTEX_LOGIN_SECRET_USER_A_USERNAME/PASSWORD`、`ARTEX_LOGIN_SECRET_USER_B_USERNAME/PASSWORD`。服务端启动时将 `ARTEX_LOGIN_SECRET_` 前缀变量移入会话管理器内存并从进程环境移除，只给登录脚本注入，避免 Agent 的 Bash/MCP 子进程直接继承。不要把凭据写入任务描述、脚本或源码目录。脚本需要自行为应用的代理/CA 设置负责。这是凭据传递隔离，不是对任意本机进程或 Agent 文件访问的 OS 沙箱。
4. 混合模式另外填写目标站点和下面的登录身份配置。只读源码审计不需要站点、登录脚本或账号。

代码包在点击「创建」时上传并解压到该任务专属目录，任务事务提交后才启动审计。取消表单不会留下服务器上传文件；创建失败会清理本次解压内容。支持 ZIP（最多 128 MiB），解压总计最多 512 MiB、单文件最多 32 MiB、最多 50000 个条目；拒绝越界路径、软链接和特殊文件。自动识别 GitHub 等 ZIP 常见的单层项目包装目录，忽略 macOS 打包元数据。建议打包前排除 node_modules、构建产物和无关大文件。

```json
[
  {"name":"user_a","script_path":"auth/login.py","identity_path":"/api/me","subject_field":"id"},
  {"name":"user_b","script_path":"auth/login.py","identity_path":"/api/me","subject_field":"id"}
]
```

`subject_field` 支持点分 JSON 路径，如 `data.user.id`。登录脚本声明的 subject 必须与该接口返回值一致。身份验证使用 GET，返回 200 才接受。profile 标签不代表身份；横向越权对照还要求两个 subject 不同。

## API

`POST /api/tasks` 使用 `multipart/form-data`：字段 `task` 为任务 JSON，字段 `source` 为 ZIP 文件。`task` 示例：

```json
{
  "description":"授权测试 https://test.example.com，只测试提供的账号与测试订单",
  "goal":"审计订单模块并验证对象级授权，交付可复现问题和未验证候选",
  "assessment":{
    "mode":"hybrid",
    "revision":"COMMIT_SHA",
    "base_url":"https://test.example.com",
    "profiles":[
      {"name":"user_a","script_path":"auth/login.py","identity_path":"/api/me","subject_field":"id"},
      {"name":"user_b","script_path":"auth/login.py","identity_path":"/api/me","subject_field":"id"}
    ]
  }
}
```

服务器自动填充 `assessment.source_path` 和 `source_archive`（文件名、SHA256、文件数、解压字节数）。客户端无需提供路径。旧的 JSON/source_path API 仍保留兼容性，但创建表单已经移除路径输入。

```sh
curl -H 'Authorization: Bearer YOUR_TOKEN' \
  -F 'task={"description":"审计上传源码","goal":"审计权限控制并交付代码候选","assessment":{"mode":"code_audit"}}' \
  -F 'source=@/path/to/project.zip' \
  http://127.0.0.1:8797/api/tasks
```

`GET /api/tasks/{id}/assessment` 返回配置。上传源码存于任务自身目录，随任务文件归档/恢复；删除任务并选择删除任务文件时会一并清理源码。配置随 origin fact 保存，不会只读继承来源任务的认证上下文。已有任务暂不支持替换源码，请重新上传并创建新任务。

## 执行与工具

Planner 的原始 Prompt 即使已在数据库中编辑，也会追加审计配置与交接约定。`add_intent` 支持 `lane=code|dynamic|authz_verify`，缺省为 dynamic。批量提交时每个元素都应明确 lane。

code lane 在工具装配完成后应用白名单，不提供 Bash、MCP、文件写入、WebFetch/Search 和 report_finding。它提供 `code_list_files`、字面量 `code_search`、按行 `code_read`、`record_code_hypothesis`，以及图读取/事实工具。

候选保存为 `fact_type=code_hypothesis`、`confidence=inferred`，每个引用包含 path、行号、revision、当时片段和 SHA256。Planner 基于这个 fact 派生验证意图。`fact.state=confirmed` 是现有图的知识记录状态，不表示该漏洞已确认；看 confidence 和 validation_status。

动态 Worker 可以用 `list_auth_profiles`、`refresh_auth_profile`、`http_request_as`、`authz_compare`。后者只发送 GET，并返回 owner/attacker/anonymous 的实际响应，不根据 200 或 hash 自动判漏洞。手工写请求仍通过 `http_request_as`，遵守任务约束；工具不会因登录过期自动重放写请求。

请求仅允许 `base_url` 的相同 scheme/host/port，重定向也受此约束，并检查现有全局/任务资产拦截规则。服务端独立持有每个 task/profile 的 CookieJar 与登录输出，第一次请求或过期时运行登录脚本；每次使用缓存身份前先检查身份接口，发现登录失效则重新登录一次再执行目标请求，避免匿名响应污染越权结论。30 秒脚本超时、64 KiB 输出上限、HTTP 20 秒超时。目标请求收到 401/419 会使缓存失效，下一次请求重新登录，也可以显式刷新。

登录 JSON 接口：

```json
{
  "cookies":[{"Name":"sessionid","Value":"SECRET","Path":"/","Secure":true}],
  "headers":{"Authorization":"Bearer SECRET","X-CSRF-Token":"SECRET"},
  "identity":{"subject":"1001","role":"user"},
  "expires_at":"2026-10-14T10:00:00Z"
}
```

未提供 expires_at 时缓存 15 分钟。动态响应脱敏已知 Cookie/Header 值；登录 stdout/stderr 不进入 Activity。其他业务敏感数据仍可能出现在工具响应，原始 HTTP 流量也会包含认证头，应按现有管理权限保护流量库。浏览器 storage、MFA 和应用特定 CSRF 刷新暂由登录脚本处理。

通过现有记录代理发送验证请求，附 `X-Artex-Request-ID`。用 `traffic_search` 的正文/请求头检索这个 ID，再 `traffic_get` 核实并绑定真实流量 ID，不能把 request_id 当成 traffic_id。关闭捕获时保留请求观察，但不会产生 HTTP 流量证据。

## 当前边界

第一版复用同一 Worker 和 LLM 配置，通过 lane 切换能力；独立 CodeWorker 模型配置、AST/调用图、自动污点追踪、候选状态管理和结构化 finding_code_refs UI 尚未实现。源码片段在候选 fact 中持久化，动态报告需要引用该 fact 并保留源码证据。

动态 `report_finding` 可以提交 `code_fact_ids`，服务器核实这些 ID 属于本任务代码候选，并将原始引用片段和版本附入漏洞 evidence，避免报告链路丢失代码证据。候选不因引用而自动改状态。

只读源码模式的 Planner/MainAgent/Worker 均禁用网络和 Bash。混合模式动态 Worker 仍拥有原有工具，应使用专用身份请求工具保留会话与证据；源码读取工具的路径限制不会改变其他黑盒工具的行为。

登录态仅驻留内存，服务器重启后自动重新登录。身份检查会发现主体失效/改变；资源接口特有的业务码、动态 CSRF 或浏览器状态仍可能需要观察响应并显式刷新，不能保证任意应用永不失效。role 来自脚本声明，subject 经身份接口核实；需要核查实际业务权限。建议为两个身份使用独立测试账号。
