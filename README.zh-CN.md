# FightRE

**面向 AI Agent 时代的五层反逆向工程防御组件 —— 零运行时依赖。**

[![ci](https://github.com/jeremyphp/fightre/actions/workflows/ci.yml/badge.svg)](https://github.com/jeremyphp/fightre/actions/workflows/ci.yml)
[![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
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
$ fightre native ./dist    # 符号表、DWARF/PDB、PIE/NX/RELRO 加固姿态
$ fightre selfcheck        # 当前进程是否被调试器/Frida 插桩？
$ fightre manifest sign ./dist --out build.manifest.json
$ fightre selftest         # 校验密码学原语
```

## 背景：REA 为什么火

2026 年 10 月，REA（Reverse Engineer Anything）三天涨了约 **7–8 万 Star**，登顶
GitHub Trending。它不是新的反汇编器，而是**一个让大模型驱动完整逆向工具链的 MCP
服务**：Ghidra、IDA、Hopper、JEB、Rizin、JADX、Frida、GDB、Playwright、CDP、
mitmproxy、tshark、binwalk 全在它的工具目录里，每条观察都记成带置信度与来源的**证据**。

三个性质决定了它的冲击力：

1. **本地运行**：样本从不上传，云端没有"这个二进制正在被逆向"的检测点。防御只能
   做在你的产物、协议、服务和数据里。
2. **经验不再是瓶颈**：你说目标，Agent 自己挑引擎、串证据、写结论。
3. **输出是语义化的**：它给你的不是一屏汇编，而是"剪贴板桥接是这么做的"加引用，
   还附一份"哪些仍未证实"的清单。

而第三点正是它的软肋：**Agent 只和它能收集到的证据一样强。** 喂它错证据，它就会
自信地写出错误的重构。

完整原理拆解见 **[docs/REA.md](docs/REA.md)**。

## 我针对它做了什么

| 攻击面 | 为什么可打 | FightRE 的做法 |
| --- | --- | --- |
| **每条已证实事实的成本** | 每条结论都要 Tool 调用、Token 和等待时间 | 工作量证明挑战、按身份的预算、有上限的 tarpit |
| **证据一致性** | Agent 相信自己观测到并引用的东西 | 伪造的 OpenAPI + 诱饵端点，返回可信但错误的数据 |
| **可追溯性** | 被拿走的记录会进入报告、仓库、数据集 | 金丝雀令牌、零宽水印、跨 worker 归因 |
| **你发出去的东西** | 符号、source map、schema、密钥都是免费的分析输入 | `fightre audit`、`fightre native`、签名构建清单 |
| **真相放在哪** | 客户端代码可读，服务端不可读 | 用证明过的会话守住真正值钱的逻辑 |

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
FightRE artifact audit - examples/leaky-dist
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

## 浏览器之外：原生、运行时、防篡改

HTTP 层看不到的地方，由另外三条命令补上：

**`fightre native`** 直接解析 ELF / PE / Mach-O 头（不做反汇编），给静态分析
"白送"的东西打分：

```
$ fightre native ./dist
  binaries : 3 (skipped 12)
  score    : 83.2/100 (worst binary)

  binary              arch       strip  dwarf  pie  nx   relro  score
  ...\dist\app        x86-64     no     no     no   no   no     83.2
  ...\dist\libcore.so aarch64    yes    yes    yes  yes  yes    0.0
```

**`fightre selfcheck`** 回答"这个进程现在被插桩了吗"：附加的调试器、`/proc/self/maps`
里的 Frida agent、默认端口、库预加载。失败项映射成服务端已经认识的同名信号。

**`fightre manifest`** 对构建做"路径 + 大小 + SHA-256"的签名清单，之后校验：
被改、缺失、被添加的文件都会报出来。随构建发布、启动时校验，任何没被动过的部署
都能自证清白。

Android（root、Frida、调试器、模拟器、Xposed）与 iOS（越狱、`P_TRACED`、Frida、
App Attest）参考实现放在 [`native/`](native/README.md)，并把 Play Integrity /
App Attest 的接口留在真正有硬件信任根的位置。原则一致：**客户端检查只提供线索，
服务端才做裁决。**

## 一个构建，多个 worker

把 `redis.enabled` 打开，内存版的 nonce、限流、金丝雀、路径多样性存储会切到
Redis——用的是内置 RESP 客户端，依旧零依赖。防重放和金丝雀归因变成集群级；
Redis 挂了则每个存储降级回本地双胞胎，服务继续可用。

```bash
$ fightre stores --config fightre.json
{"backend": "redis", "ok": true, "errors": 0}
```

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
  signals.py        五层 51 个信号
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
  native.py         ELF/PE/Mach-O 加固与符号审计
  instrumentation.py 调试器/Frida 自检
  manifest.py       签名构建清单
  stores.py         内存 / Redis 共享状态
  redis.py          零依赖 RESP2 客户端
  client/fightre.js 浏览器端证明
native/             Android / iOS 参考守卫与移动端文档
demo/run_demo.py    端到端实测
docs/               威胁模型、架构、部署、信号目录
tests/              145 个单元测试
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
- 速率限制、防重放与金丝雀归因默认是进程内的；打开 `redis.enabled` 才跨 worker。
  没有共享存储时，多 worker 需要会话粘滞。

## 路线图

- ~~Redis 版 nonce/限流存储，支持多 worker~~（0.2.0 已完成）
- ~~原生产物审计、运行时自检、构建清单~~（0.2.0 已完成）
- Rust/C++ 运行时 shim：桌面端进程内完整性校验与硬件证明接入。
- 按会话的响应多态：每条响应带不同水印，一条泄露记录就能定位到会话而不只是租户。
- 基于审计日志的权重自动调优（误报反馈闭环）。

## 负责任使用

FightRE 用于保护你拥有或运营的软件。不得用于干扰他人的工具或取证证据，也不得用于
阻挠经过授权的安全研究。详见 [SECURITY.md](SECURITY.md) 与
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)。

## 文档

- [设计说明](docs/DESIGN-RATIONALE.md)：每一层为什么存在、能看到什么、代价是什么
- [威胁模型](docs/THREAT-MODEL.md)：REA 能做什么，逐项对应
- [架构](docs/ARCHITECTURE.md)：流水线、评分、状态、扩展点
- [部署](docs/DEPLOYMENT.md)：框架接入、边缘指纹、灰度上线
- [信号目录](docs/SIGNALS.md)：51 个信号，由代码生成
- [原生与移动端](native/README.md)：二进制审计、自检、Android/iOS 守卫

## 许可

**Apache-2.0** —— 见 [LICENSE](LICENSE)、[NOTICE](NOTICE)、[TRADEMARK.md](TRADEMARK.md)。

可以商用、可以嵌入、可以 fork、可以打包进你的产品。不收费、不传染、不用问。

选 Apache-2.0 而不是 MIT，只为一个实际原因：**专利授权**。MIT 对专利只字未提，
企业把它装进产品时，法务会问"如果贡献者后来拿专利起诉我们怎么办"——MIT 回答不了，
Apache-2.0 §3 回答得了，而且有专利反制条款兜底。对一个跑在生产链路里的组件，
这就是"能用"和"不能用"的差别。

我们刻意**没有**选 AGPL 或 source-available。防御组件的价值在于被广泛部署、被公开
攻击；一个把企业挡在门外的协议，会把本项目最需要的反馈也挡在门外。

贡献采用 [DCO](CONTRIBUTING.md#sign-off-dco)（`git commit -s`），不用 CLA。

| 需要什么 | 去哪 |
|---|---|
| 社区帮助 | [SUPPORT.md](SUPPORT.md)、Discussions |
| 商业支持 / 私有部署 | [SUPPORT.md](SUPPORT.md) |
| 名称与标识使用 | [TRADEMARK.md](TRADEMARK.md) |
