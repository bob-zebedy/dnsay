# dnsay

把 DNS 服务变为一个加密群聊室。基于 DNS TXT 记录的端到端加密群聊系统: 消息通过 DNS 查询隧道传输，服务端作为盲转发器，无法读取消息内容。

---

## 快速开始

### 本地编译运行

```bash
git clone git@github.com:bob-zebedy/dnsay.git
cd dnsay
go mod download
make
./bin/dnsany-server   # 服务端
./bin/dnsay           # 客户端
```

### Docker 部署服务端

```bash
git clone git@github.com:bob-zebedy/dnsay.git
cd dnsay
make docker
docker-compose up -d
```

### 命令行参数

**服务端**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--bind` | string | `0.0.0.0` | 绑定地址 |
| `--port` | int | `5335` | 监听端口 |
| `--timeout` | int | `300` | 会话空闲超时(秒) |
| `--verbose` | bool | `false` | 调试模式 |

**客户端**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--name` | string | (自动生成) | 昵称 |
| `--group` | string | `default` | 分组 ID(同时作为加密密钥材料) |
| `--dns` | string | `127.0.0.1:5335` | DNS 服务器地址 |
| `--interval` | float64 | `0.25` | 基准轮询间隔(秒) |
| `--verbose` | bool | `false` | 调试模式(启用 TUI 内 DEBUG 区) |

### TUI 操作

| 按键 | 行为 |
|------|------|
| `Enter` | 发送消息 |
| `Ctrl+J` | 输入框内插入换行 |
| `↑` / `↓` | 切换历史输入记录 |
| `←` / `→` | 在当前文本内移动光标 |
| `PgUp` / `PgDn` | 滚动消息区 |
| `Alt+PgUp` / `Alt+PgDn` | 滚动 DEBUG 区(仅 verbose) |
| `End` | 跳到最新消息 |
| `Esc` / `Ctrl+C` | 退出 |

---

# 协议文档

## 架构概览

```
┌──────────┐    DNS TXT Query     ┌──────────┐    DNS TXT Query     ┌──────────┐
│ Client A ├─────────────────────>│  Server  │<─────────────────────┤ Client B │
│          │<─────────────────────┤ (盲转发)  ├─────────────────────>│          │
└──────────┘    DNS TXT Reply     └──────────┘    DNS TXT Reply     └──────────┘
     │                                                                    │
     │            E2E Key = HMAC-SHA256("dnsay-key-v1", group)            │
     └───────────────────── group 名 (共享密钥) ────────────────────────────┘
```

- **Client**: 负责 E2E 加密/解密、DNS 编码、TUI 交互、昵称注册
- **Server**: DNS 服务器，负责会话管理、消息中继、昵称去重，**不接触加密密钥**

## 密钥与路由分离

group 名同时用于路由和加密，但通过不同的 HMAC 路径派生，实现域分离: 

| 用途 | 派生方式 | 长度 | 可见性 |
|------|---------|------|--------|
| 路由 ID | `HMAC-SHA256("dnsay-route", group)[:8]` | 8 字节 | DNS 流量中可见(base32 编码) |
| 加密密钥 | `HMAC-SHA256("dnsay-key-v1", group)` | 32 字节 | 仅客户端持有，不传输 |

**安全性**: DNS 观察者只能看到路由 ID(8 字节哈希)，无法反推 group 名，也无法推导加密密钥。

## DNS 查询名格式 (QName)

所有通信通过 DNS TXT 查询实现。查询名 (qname) 的标签格式: 

```
<RouteID>.<SID>.<Dir>.<Seq-Total>.<QueryNonce>[.<Payload>...].
```

| 标签位置 | 内容 | 编码 | 说明 |
|---------|------|------|------|
| 0 | 路由 ID | base32, 无 padding, 小写 | 8 字节 HMAC 哈希，用于会话匹配 |
| 1 | 会话 ID | base32, 无 padding, 小写 | 8 字节随机值，客户端启动时生成 |
| 2 | 方向 | 明文 | `u`/`p`/`j`/`l` |
| 3 | 序号-总数 | 明文 | 上传 `seq-total`(如 `0-3`)，其他方向为 `0` |
| 4 | 查询 Nonce | base32, 无 padding, 小写 | 12 字节随机值，防 DNS 缓存命中 |
| 5+ | 载荷 | base32, 无 padding, 每 30 字符一个标签 | 仅 `u` 和 `j` 方向需要 |

**重要**: 载荷使用 base32 而非 base64url。原因是 base64url 的字母表包含 `-`，DNS 标签**不允许以 `-` 开头**(RFC 1035)，会被 Go resolver 拒绝并返回 `no such host` 错误。base32 字母表(A-Z + 2-7)完全规避此问题。

### 方向 (Dir) 说明

| 方向 | 含义 | 载荷 | 服务端响应 |
|------|------|------|-----------|
| `u` | 上传消息 | E2E 密文分块 | `ok`(已注册)/ `unreg`(未注册) |
| `p` | 轮询消息 | 无 | base64url 编码的多消息帧 |
| `j` | 注册昵称 | base32(昵称字节) | `ok`(成功) / `dup`(重名) / `bad`(空昵称或过长) |
| `l` | 离开 | 无 | `ok` |

## E2E 加密流程

### 加密(发送方)

```
plaintext = nickname + '\x00' + message_text
    │
    ▼
msgNonce = random(12 bytes)
    │
    ▼
e2e_ct = AES-256-GCM.Encrypt(
    key   = HMAC-SHA256("dnsay-key-v1", group),         // 32 字节
    nonce = msgNonce,                                   // 12 字节
    data  = plaintext,
    aad   = group                                       // 原始 group 名作为附加认证数据
)
    │
    ▼
wire_data = msgNonce(12) || e2e_ct(len + 16)
```

### 解密(接收方)

```
wire_data
    │
    ├─ msgNonce = wire_data[:12]
    ├─ e2e_ct   = wire_data[12:]
    │
    ▼
plaintext = AES-256-GCM.Decrypt(
    key   = HMAC-SHA256("dnsay-key-v1", group),
    nonce = msgNonce,
    data  = e2e_ct,
    aad   = group
)
    │
    ├─ nickname = plaintext[:null_byte_index]
    └─ message  = plaintext[null_byte_index+1:]
```

### 加密参数

| 参数 | 值 |
|------|-----|
| 算法 | AES-256-GCM |
| 密钥长度 | 32 字节 |
| Nonce 长度 | 12 字节(随机) |
| Tag 长度 | 16 字节 |
| AAD | group 名原始字节 |
| 每消息开销 | 28 字节(12 nonce + 16 tag) |

## 分块传输机制

### 发送方分块

E2E 密文按 **80 字节** 分块，每块作为独立 DNS 查询发送。每块**重试最多 3 次**: 

```
wire_data (nonce || ciphertext || tag)
    │
    ▼ 按 80 字节切割
┌──────────┐ ┌──────────┐ ┌──────────┐
│ chunk 0  │ │ chunk 1  │ │ chunk 2  │  ...
│ (80B)    │ │ (80B)    │ │ (<=80B)  │
└────┬─────┘ └────┬─────┘ └────┬─────┘
     │            │            │
     ▼            ▼            ▼
  DNS Query    DNS Query    DNS Query
  seq=0-3      seq=1-3      seq=2-3
  (重试3次)     (重试3次)     (重试3次)
```

每个分块的 DNS 查询: 
1. 生成 12 字节随机 QueryNonce(仅防 DNS 缓存)
2. 分块 base32 编码，每 30 字符一个 DNS 标签
3. 组装 qname: `RouteID.SID.u.seq-total.QueryNonce.payload_labels...`
4. 发送 DNS TXT 查询；失败则**生成新 QueryNonce 重试**(最多 3 次)

### 服务端重组与校验

进入 `addChunk` 前先做参数边界检查(`isValidUpload`): 

- `1 ≤ total ≤ maxUploadChunks (64)`
- `0 ≤ seq < total`
- `1 ≤ len(payload) ≤ maxUploadChunkSize (96)`

不满足则直接回复 `bad`，丢弃。

```go
addChunk(sid, seq, total, payload)
```

- 按 `(sid, total)` 缓冲分块，`bytes` 字段累计已收字节
- `seq == 0` 时重置缓冲区(处理前一条未完成的消息)
- 同 `seq` 重复发送会覆盖旧值，`bytes` 自动差量更新
- 累计字节数超过 `maxUploadTotal (4124)` → 立即丢弃整个缓冲，防止内存爆
- 全部块到齐后按序拼接，广播完整 E2E 密文到组内其他会话

### 大小限制

| 参数 | 值 | 来源 |
|------|----|------|
| 最大消息载荷 | 4096 字节 | `client/main.go: maxPayloadSize` |
| 分块大小 | 80 字节 | `client/main.go: chunkSize` |
| 分块重试次数 | 3 次 | `client/main.go: chunkRetries` |
| DNS 标签段长 | 30 字符 | `shared.LabelSegLen` |
| DNS 标签上限 | 63 字符 | RFC 1035 |
| DNS qname 上限 | 253 字符 | RFC 1035 |
| TXT 单条字符串上限 | 200 字符 (base64url) | `server/main.go: maxTXTLength` |
| 服务端单查询载荷上限 | 96 字节 | `server/main.go: maxUploadChunkSize` |
| 服务端最大分块数 | 64 | `server/main.go: maxUploadChunks` |
| 服务端重组累计上限 | 4124 字节 | `server/main.go: maxUploadTotal` |
| 昵称字节上限 | 64 字节 | `server/main.go: maxNameBytes` |
| 单会话 downq 容量 | 1024 条 | `server/main.go: maxDownqMsgs` |

## Poll 响应帧格式

服务端返回多条消息时使用长度前缀帧格式: 

```
┌─────────────────────────────────────────────────────────┐
│ 2B len │ E2E blob 1 │ 2B len │ E2E blob 2 │ ...         │
└─────────────────────────────────────────────────────────┘
                │                      │
                ▼                      ▼
            nonce(12)              nonce(12)
            ct(N+16)               ct(N+16)
```

- **长度前缀**: 2 字节大端序 uint16，表示后续 E2E blob 长度
- **E2E blob**: `msgNonce(12) || AES-GCM-Ciphertext || Tag(16)`
- 多条消息顺序拼接
- 空响应时返回空字符串 TXT 记录

### 响应大小限制

| 参数 | 值 |
|------|-----|
| 每次 poll 最大消息数 | 10(`maxPollCount`) |
| 每次 poll 最大字节数 | 4096(`maxPollBytes`) |
| TXT 记录最大长度 | 200 字符 base64url |

### DNS 传输

帧数据 → base64url 编码 → 按 200 字符切分 → 每段作为一条 TXT 记录回复。

客户端: 拼接 TXT 记录 → base64url 解码 → 解析帧 → 逐条 E2E 解密。

## 自适应轮询

```
             收到消息
               │
    ┌──────────▼──────────┐
    │ interval = 250ms    │◀─── 立即回到快速轮询
    │ (baseInterval)      │
    └──────────┬──────────┘
               │ 无消息
               ▼
    ┌─────────────────────┐
    │ interval *= 2       │
    │ cap at 2s           │
    │ (maxInterval)       │
    └──────────┬──────────┘
               │ 无消息
               ▼
          继续倍增直到 2s
```

- 活跃聊天: 每 250ms 轮询一次
- 空闲时: 250ms → 500ms → 1s → 2s(封顶)
- 任意消息到达: 立即回到 250ms

## 昵称管理

### 注册流程

1. 客户端启动时调用 `RegisterName`
2. 客户端发送 `j` 方向请求带上昵称(载荷 ≤ `maxNameBytes` 64 字节)
3. 服务端检查载荷长度: 空或 > 64 字节 → 回复 `bad`
4. 服务端检查同组(routeID)下是否已存在该昵称: 
   - 不存在 → 在该 SID 上注册昵称，回复 `ok`
   - 已存在 → 回复 `dup`
5. 客户端收到 `dup`: 
   - 命令行**未指定** `--name`(auto 模式): 自动调用 `nickname()` 重新生成，最多重试 10 次
   - 命令行**显式指定** `--name`: 直接退出，提示昵称冲突

### 离开流程

- **主动关闭**(ESC / Ctrl+C): 客户端发送 `l` 方向请求，服务端立即删除会话和昵称
- **被动断开**(崩溃 / 断网): 会话最后活跃时间停止更新，超过 `--timeout`(默认 300 秒)后被 `cleanup` 删除，昵称随之释放

### 会话过期自动恢复

如果会话被服务端清理(如长时间网络中断后恢复)，客户端再次发送消息时: 
1. 服务端 `touch` 创建新 session(无昵称)
2. 服务端回复 `unreg` 而不是 `ok`
3. 客户端检测到 `unreg`，自动调用 `registerOnce()` 重新注册昵称

## 完整消息生命周期

```
 Client A (发送方)                   Server                    Client B (接收方)
 ──────────────────                 ────────                  ──────────────────
 1. 用户输入 "你好"
 2. 构建 payload:
    "飞翔的开拓者\x00你好"
 3. E2E 加密:
    nonce(12) || AES-GCM(...)
 4. 分块 (80B each)
 5. 每块 → DNS TXT Query
    qname: RouteID.SID.u.0-1...
    (失败自动重试最多 3 次)
                                    6. 解析 qname (base32 解码)
                                    7. addChunk 重组
                                    8. broadcast → B.downq
                                    9. 回复 "ok"/"unreg"
                                                              10. Poll Query
                                                                  qname: RouteID.SID.p.0...
                                    11. popMessages
                                    12. 帧编码 + base64url
                                    13. TXT 记录回复
                                                              14. base64url 解码
                                                              15. 解析帧
                                                              16. E2E 解密
                                                              17. 解析 name\x00message
                                                              18. TUI 显示:
                                                                  "飞翔的开拓者: 你好"
```

## 服务端会话状态

每个 SID 对应一个 `session`: 

```go
type session struct {
    grp    []byte       // 路由 ID(同组归属)
    name   string       // 注册的昵称(可能为空)
    downq  [][]byte     // 待投递消息队列
    last   int64        // 最后活跃时间戳
    msgBuf *msgBuffer   // 多块上传重组缓冲
}
```

服务端职责: 
- 解析 DNS qname 提取路由 ID 和会话 ID
- 按路由 ID 匹配同组会话
- 重组分块消息
- 广播 E2E 密文到组内其他会话
- 注册和检查昵称唯一性
- 管理会话生命周期(10 秒一次 cleanup，超时清理)
- **不持有任何加密密钥，不解密消息内容**

**downq 溢出策略**: 当某个会话的待投递队列长度达到 `maxDownqMsgs (1024)` 时，新消息入队会丢弃最旧的一条(drop-oldest FIFO)，避免僵尸/恶意会话导致内存无限增长。
