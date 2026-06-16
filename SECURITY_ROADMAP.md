# Unicorn CRM 安全靶场升级路线图

创建时间：2026-06-16

## 当前定位
Web 基础攻防靶场，覆盖 OWASP Top 10 约 60%，对应初级→中级安全培训。

## 升级目标
企业级安全培训靶场，覆盖 OWASP Top 10 全部 + Web 2.0/API + 云原生安全，
对应中级→高级红蓝对抗训练。

---

## Phase 1: OWASP Top 10 全覆盖（缺口补齐）

| # | 模块 | 攻击面设计 | 级别 |
|---|------|-----------|------|
| 1.1 | SSRF | 文件导入模块：用户输入 URL → 服务器 fetch。可探测内网（metadata/redis/elasticsearch）。需开放 `/admin/import-url` ✅ 和 `/admin/fetch-external` 两个入口 | 🔴 High |
| 1.2 | XXE | 合同/发票上传支持 XML 格式。`/files/upload-xml` 解析含外部实体的 XML。可读取 `/etc/passwd`、SSRF、DoS（Billion Laughs） | 🔴 High |
| 1.3 | JWT 攻击 | 开放 `/api/auth/token` 端点。算法混淆（none/RSA→HMAC）、密钥爆破（弱 secret）、kid 注入。需要改 `middleware/api-auth.js` 加默认 JWT secret 为弱密钥 | 🟠 Medium |
| 1.4 | CORS 配置弱点 | 故意在特定端点（如 `/api/v1/public`）配置宽松 CORS，让学员练习凭证窃取、Origin 绕过 | 🟡 Medium |
| 1.5 | SSTI | /api/report-preview 使用用户可控模板变量渲染。EJS 在特定配置下可致 RCE（`<%- userInput %>` 而非 `<%= %>`） | 🔴 High |
| 1.6 | IDOR 深度 | 现有 IDOR 太浅。需要多层级：/api/orders/:id、/api/tickets/:id、/api/users/:id/invoices —— 都缺少归属校验 | 🟠 Medium |
| 1.7 | OS 命令注入 | `/admin/system-check` 调用 `child_process.exec()` 拼接用户输入（ping/traceroute 工具）。练习命令注入 + 字符过滤绕过 | 🔴 High |
| 1.8 | 不安全的反序列化 | Node.js 用 `node-serialize` 解析 cookie（`profile` cookie 经 base64+serialize）。学员可构造 RCE payload | 🔴 High |
| 1.9 | 日志伪造/注入 | 登录日志未清洗用户输入，`\n` 注入可伪造日志行（掩盖攻击痕迹） | 🟡 Low |
| 1.10 | CSP 绕过 | 现有 CSP 策略很严格。内嵌一个含 unsafe-eval 的页面（`/admin/widgets`），练习 CSP 绕过 + data URI XSS | 🟠 Medium |

---

## Phase 2: 云原生 & 容器安全

| # | 模块 | 设计 | 级别 |
|---|------|------|------|
| 2.1 | Docker 化部署 | 将应用容器化（Dockerfile），在容器中暴露 `/var/run/docker.sock` 挂载 → 容器逃逸 | 🔴 High |
| 2.2 | K8s 环境 | 部署到 minikube/k3s，暴露 service account token。练习 RBAC 提权、etcd 访问 | 🔴 High |
| 2.3 | Serverless 注入 | 模拟 Lambda 函数，Event Injection、依赖投毒 | 🟡 Medium |
| 2.4 | CI/CD 投毒 | `.github/workflows` 暴露可写。练习 pipeline injection、secret 窃取 | 🔴 High |

---

## Phase 3: API & 现代 Web 攻击

| # | 模块 | 设计 | 级别 |
|---|------|------|------|
| 3.1 | REST API 滥用 | 开放 `/api/v2` 新版 API。Mass Assignment、批量操作竞态条件、参数污染（?user=admin&user=basic） | 🟠 Medium |
| 3.2 | GraphQL 深度攻击 | 在现有基础上加：Batch Query 绕过限流、Fragment 展开 DoS、Subscription hijacking、Alias 绕过复杂度限制 | 🟠 Medium |
| 3.3 | WebSocket 劫持 | `/ws/chat`：CSWSH 漏洞（Origin 不校验）、消息注入、频道越权（加入别人的 room） | 🟠 Medium |
| 3.4 | WebRTC/STUN 泄露 | 视频会议模块（模拟），STUN 服务器泄露内网 IP | 🟡 Low |
| 3.5 | OAuth 2.0 漏洞 | 实现完整 OAuth flow（授权码模式）。CSRF 在 /authorize、open redirect 在 redirect_uri、client_secret 泄露、PKCE 缺失 | 🔴 High |

---

## Phase 4: 高级持久化 & 蓝队检测

| # | 模块 | 设计 | 级别 |
|---|------|------|------|
| 4.1 | C2/Callback | 文件上传不校验内容可执行（`.js` / `.wasm`），提供 Node.js `child_process` 执行链 | 🔴 High |
| 4.2 | 持久化后门 | Cron job 写入、`.bashrc` 修改、systemd service 创建。模拟攻击者留下后门 | 🔴 High |
| 4.3 | 横向移动网络 | 部署虚拟子网（Docker network），靶机内另一容器跑 Redis/MySQL（弱口令或无密码）。SSH 密钥信任 | 🔴 High |
| 4.4 | 数据渗出 | 数据库含 PII（姓名/电话/邮箱），练习 DLP 检测绕过（base64 分段、DNS exfiltration、ICMP tunneling） | 🟠 Medium |
| 4.5 | Windows AD 模拟 | Linux 上用 Samba4 模拟 AD 域。Kerberoasting、AS-REP Roasting、LDAP 枚举、GPP 密码、黄金票据/白银票据 | 🔴 High |
| 4.6 | 日志 & SIEM 集成 | 集成 ELK Stack，写攻击产生的日志特征，供蓝队练习威胁狩猎（Threat Hunting） | 🟡 Medium |

---

## Phase 5: 培训体系化

| # | 组件 | 说明 |
|---|------|------|
| 5.1 | 任务面板 | Flask/Django 单页：学员选模块 → 看 hint → 提交 flag → 计分 |
| 5.2 | Walkthrough 文档 | 每个漏洞含：漏洞介绍、攻击步骤、PoC、修复方案、防御代码 |
| 5.3 | CTF 模式 | 限时挑战：60分钟/模块，排行榜。多角色协作（红/蓝队） |
| 5.4 | Docker Compose 一键部署 | 5分钟启动全部模块 |

---

## 优先级建议

```
立即（本周可做）：Phase 1 — SSRF / XXE / 命令注入 / SSTI / 不安全的反序列化
短期（2周内）：  Phase 1 剩余 + Phase 3.1-3.3 (REST/GraphQL/WS)
中期（1个月）：  Phase 3.4-3.5 (WebRTC/OAuth) + Phase 2.1-2.2 (Docker/K8s)
长期（2-3个月）：Phase 4 (C2/AD/横向移动) + Phase 5 (培训体系)
```

---

## 当前即刻可落地（Phase 1 前 5 个）

| 模块 | 新建文件 | 改动文件 | 预估工作量 |
|------|---------|----------|-----------|
| SSRF | `routes/admin/import.js` | `app.js`（加路由） | 15分钟 |
| XXE | `routes/files/xml.js` | `routes/files.js`（注册子路由） | 15分钟 |
| 命令注入 | `routes/admin/system.js` | `app.js` + `views/admin/system.ejs` | 20分钟 |
| SSTI | `routes/api/report.js` | `app.js` + `views/api/report.ejs` | 15分钟 |
| 不安全反序列化 | `middleware/cookie-profile.js` | `app.js`（注册中间件） | 20分钟 |

总计约 1.5 小时可完成 5 个 high-impact 模块。
