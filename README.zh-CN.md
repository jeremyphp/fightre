# FightRE

**面向 AI Agent 时代的五层反逆向工程防御组件 —— 零运行时依赖。**

[![ci](https://github.com/your-org/fightre/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/fightre/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)

REA（Reverse Engineer Anything）把逆向工程变成了一条 Agent 流水线：一个 MCP
服务把 Ghidra、IDA、Frida、JADX、Playwright、mitmproxy 和大模型串成一个闭环，
本地运行、不上传样本，产出带"证据链"的报告，再由模型改写成可运行代码。

**你无法让别人的机器上的二进制变成不可读。** 但你可以让提取成本变高、让自动化
拿到自相矛盾的证据、让任何泄露物都能追溯到泄露它的那个会话。FightRE 就是这件事，
做成一个零依赖的 Python 包 + 浏览器端脚本，外加一个"上线前体检"：告诉你在 Agent
眼里，你的构建产物五分钟能泄露多少东西。

```
$ fightre serve            # 带防护的演示服务
$ fightre audit ./dist     # 这份构建产物会被 REA 拿走什么？
$ fightre selftest         # 校验密码学原语
```

## 一句话看懂五层

| 层 | 回答的问题 | 机制 |
| --- | --- | --- |
| **L0 构建产物** | 我免费送出去了什么？ | `fightre audit`：source map、调试符号、硬编码密钥、公开 schema、内网域名 |
| **L1 网络层** | 这个身份是不是机器？ | 令牌桶速率预算、路径多样性爬取检测 |
| **L2 协议层** | 线上的客户端和它自称的一致吗？ | UA ↔ `sec-ch-ua` 矛盾、头部顺序、重复/走私头、JA3/HTTP2 指纹（边缘 HMAC 签名） |
| **L3 前端** | 这真的是浏览器吗？ | 工作量证明挑战、环境证明（webdriver、CDP 泄漏、原生函数被改写、软件渲染器、环境自洽性） |
| **L4 后端** | 它是在用 API，还是在拆 API？ | HMAC 请求签名、nonce 防重放、蜜罐端点、schema 探测识别、**伪造的 API 文档** |
| **L5 数据层** | 这份拷贝是谁流出的？ | 合成响应里的金丝雀令牌、字符串里的零宽水印、泄露归因注册表 |

## 实测（真实 HTTP，不是截图）

`python demo/run_demo.py` 会起一个真实的 WSGI 服务，跑真实的工作量证明：

```
scenario                             HTTP action      score  note
------------------------------------------------------------------------------
honest browser (PoW + attestation)    200 allow           0  pass
curl script                           429 challenge      40  PoW required
REA agent: schema triage              200 tarpit         83  fabricated schema, 655ms
REA agent: eats the bait              200 tarpit         92  synthetic data (canary inside), 1018ms
REA agent: replays canary             403 block          91  hard block
forged attestation                    403 block          88  hard block
spoofed JA3 edge header               403 block          88  hard block
scanner hits /.env                    200 tarpit         91  synthetic data (canary inside), 961ms
signed request (fresh)                200 allow           0  pass
signed request (replayed)             403 block          88  hard block
```

三条关键设计：

1. **不在门口拦截 Agent。** 它拿到的是 `200` + 一份伪造的 `openapi.json`，然后是
   伪造的密钥——每一个都带金丝雀。拦截会让它换打法，欺骗会让它继续烧预算、并把你
   的金丝雀带回它的笔记里。
2. **一旦使用诱饵，立刻硬阻断。** 金丝雀回传的瞬间，任何 trust 都无法覆盖判定。
3. **真实浏览器无感。** 干净的 Chrome 只解一次挑战、拿到 `HttpOnly` 证明 Cookie，
   之后零摩擦。

## 污染证据链

REA 的设计原则是 *evidence first*：每条结论都带 identity、confidence、authority、
unknowns。这恰恰是它的软肋——拿到错误证据的 Agent，会写出一份自信的错误报告。

`fightre/decoy.py` 伪造一套可信的内部接口：

```
GET /openapi.json              -> 一份完整的 OpenAPI 3.0 文档（故意是错的）
GET /api/v2/internal/keys      -> 带 canary kid 的 RSA 密钥
GET /api/v2/internal/config    -> 数据库地址、特性开关、build id
POST /api/v2/admin/impersonate -> 管理员会话令牌（canary）
```

每个凭证都是注册过的金丝雀：一旦被回放到服务（`data.canary_echo`）就硬阻断；一旦
出现在泄露数据集里，`CanaryRegistry.find()` 能定位到具体身份、路径和时间。诱饵路径
不会出现在任何真实页面里，正常客户端不可能误触。

## 上线前先体检

静态分析是 REA 流水线里最便宜的一半，而它需要的东西通常是"手滑"发出去的：

```
$ fightre audit examples/leaky-dist
FightRE artifact audit - E:\fightrea\examples\leaky-dist
  exposure : 88.3/100 - an agent would reconstruct this service quickly
  files    : 5 (1.1 KiB)
  severity : critical=2  high=3  medium=1  low=1

  [CRITICAL] sourcemap              assets\app.js.map
             A source map reconstructs the original TypeScript/JS, comments included.
             fix: Delete *.map from the deployed artifact (build with sourcemaps off).
  [CRITICAL] private-key            deploy\signing.pem:1
  [HIGH    ] dotenv                 .env
  [HIGH    ] generic-secret         assets\app.js:5
  [MEDIUM  ] sourcemap-reference    assets\app.js:17
  [LOW     ] internal-host          assets\app.js:4
```

CI 友好：`--fail-over 70` 决定退出码，`--markdown` / `--json` 输出报告。

## 快速开始

```bash
pip install -e .          # Python 3.9+，无运行时依赖
fightre keygen            # 生成 FIGHTRE_SECRET
```

**ASGI**（FastAPI / Starlette / Litestar）：

```python
from fightre import Config, FightREMiddleware
app.add_middleware(FightREMiddleware, config=Config.load("fightre.json"))
```

**WSGI**（Flask / Django / 原生 WSGI）：

```python
from fightre.wsgi import FightREWSGIMiddleware
application = FightREWSGIMiddleware(application, Config.load("fightre.json"))
```

**浏览器端**：把 `fightre/client/fightre.js` 从你自己的域名提供出去。它会采集环境
信号、解 SHA-256 工作量证明（约 0.2–1 秒），提交签名证明，服务端回一个 `HttpOnly`
Cookie。

完整部署说明见 [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)。

## 评分与策略

每个检测器输出一个带权重的具名信号，权重按"这不是真实客户端的概率"理解，
独立证据用 noisy-OR 合成：

```
score = max(0, 100 · (1 − Π(1 − wᵢ/100)) − trust)
```

- **有界**：一堆弱信号不会悄悄堆成封禁；
- **可结合**：检测器顺序无关，可并行；
- **可解释**：每个判定都能列出信号、权重、层：

```python
score=86.4 action=tarpit
  - L2-protocol proto.bot_user_agent +40 (marker 'headlesschrome')
  - L2-protocol proto.agent_runtime +50 (User-Agent contains 'playwright')
  - L4-app app.introspection_probe +34 (/openapi.json)
  - L3-client client.missing_attestation +16 (no attestation cookie)
```

五个档位把分数映射为动作：`allow`、`challenge`（429 + PoW）、`deceive`（200 合成
数据）、`tarpit`（延迟后 200 合成数据）、`block`（403，无信息）。外加两条覆盖规则：

- **硬阻断**：伪造证明、重放签名、请求走私、未签名的边缘指纹、金丝雀回传——
  决定性证据，trust 无法覆盖；
- **迷宫规则**：碰到诱饵永远不升级为封禁。被封禁的 Agent 会重开；被欺骗的 Agent
  会继续烧预算，并替你把金丝雀带出去。

档位、权重和两张名单都在 `fightre/presets/*.json` 里，改配置不改代码。

## 目录结构

```
fightre/            包本体（仅标准库）
  guard.py          请求 → 判定
  signals.py        五层 47 个信号
  scoring.py        noisy-OR + 解释
  policy.py         档位、硬阻断、迷宫规则
  headers.py        UA/Client-Hints、头部顺序、走私
  fingerprint.py    JA3/HTTP2 接入、边缘 HMAC
  agent_detect.py   REA 工具链特征
  challenge.py      PoW、nonce 存储
  attest.py         环境证明
  signing.py        HMAC 请求签名
  decoy.py          蜂蜜 API（伪造 schema）
  deception.py      合成响应、tarpit
  canary.py         金丝雀 + 零宽水印
  artifacts.py      构建产物审计
  client/fightre.js 浏览器端证明
demo/run_demo.py    端到端实测
docs/               威胁模型、架构、部署、信号目录
tests/              102 个单元测试
```

## 设计原则

- **零依赖**：一次 `pip install`，没有供应链，没有构建步骤。
- **不能解释就不上线**：每个动作都能追溯到具名证据，`fightre explain audit.jsonl`
  直接汇总线上流量。
- **不惩罚人类**：先挑战后欺骗，先欺骗后封禁；保留白名单和豁免机制。
- **默认保护隐私**：身份用每日轮换盐做哈希，审计日志不写入请求头与请求体。
- **假设源码公开**：所有机制都必须在攻击者读过源码之后依然成立。

## 边界（诚实地读）

- 拿到二进制、又有无限时间的分析师最终会赢。FightRE 提高成本、污染证据，它不是 DRM。
- 证明只能说明"有个像浏览器的运行时执行了我们的 JS"，不能说明对面是人。
- 信号都是启发式。请用你自己的流量调权重，并预期老浏览器、企业代理、无障碍工具
  带来的误报。
- 速率限制与重放存储是进程内的。多 worker 需要会话粘滞或共享存储。

## 路线图

- Redis 版 nonce/限流存储，支持多 worker。
- 原生侧配套（Rust/C++）：符号清理、完整性自检、Frida/root 检测、硬件级证明接入。
- 按会话的响应多态：每条响应带不同水印，一条泄露记录就能定位到会话而不只是租户。
- 基于审计日志的权重自动调优（误报反馈闭环）。

## 负责任使用

FightRE 用于保护你拥有或运营的软件。不得用于干扰他人的工具或取证证据，也不得用于
阻挠经过授权的安全研究。详见 [SECURITY.md](SECURITY.md) 与
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)。

## 文档

- [威胁模型](docs/THREAT-MODEL.md)：REA 能做什么，逐项对应
- [架构](docs/ARCHITECTURE.md)：流水线、评分、状态、扩展点
- [部署](docs/DEPLOYMENT.md)：框架接入、边缘指纹、灰度上线
- [信号目录](docs/SIGNALS.md)：47 个信号，由代码生成

## 许可

MIT，见 [LICENSE](LICENSE)。
