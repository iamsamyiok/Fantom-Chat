# 贡献指南（CONTRIBUTING）

首先，**感谢**你愿意为 Fantom-Chat 贡献力量。无论是修复 Bug、改进文档、提出新功能，
还是仅仅反馈使用体验，**所有形式的贡献都受欢迎**。

本文件说明向本项目提交 Issue / PR 的流程与约定，目的是让协作顺畅、让评审者聚焦于内容本身。

---

## 1. 行为准则

- **友善与尊重**：技术分歧可以激烈讨论，但禁止人身攻击、歧视或骚扰。
- **就事论事**：评论代码、不要评论人。
- **保护隐私**：日志、截图里可能包含 IPv6 地址等可定位信息，发布前请按需打码。
- **不滥用**：本项目用于正当的隐私通信，禁止用于任何非法用途。

---

## 2. 我应该贡献到哪里？Issue 还是 Discussion？

| 场景 | 去哪里 |
|------|--------|
| 可复现的 Bug | [Issue · Bug Report](.github/ISSUE_TEMPLATE/bug_report.md) |
| 具体的新功能建议 | [Issue · Feature Request](.github/ISSUE_TEMPLATE/feature_request.md) |
| 使用疑问 / 想法 / 求助 / 讨论 | [GitHub Discussions](https://github.com/Emilianissimo/Fantom-Chat-P2P-IPv6-Chat/discussions) |
| 安全漏洞披露 | **请勿公开 Issue**，使用 [Security Advisory](https://github.com/Emilianissimo/Fantom-Chat-P2P-IPv6-Chat/security/advisories/new) |

> Issue 区只受理「可执行」的内容；Discussion 区用于发散与求助。
> 这样 Issue 列表能保持精简，便于评审与排期。

---

## 3. 提交 Issue 前请先做

1. **搜索**已有 Issue 和 Discussion，避免重复。
2. 阅读仓库根目录的 [README.md](README.md) 与 [优化建议文档](Fantom-Chat-优化建议文档.md)，
   里面可能已经回答了你的问题或包含了相关路线图。
3. 如果是 Bug，请尽量在**最新的 `main` 分支**上复现一次——可能已经修复了。
4. 填写对应模板里的**所有字段**，缺一项可能被直接关闭为 `needs info`。

---

## 4. 开发环境

| 平台 | 依赖 | 安装示例 |
|------|------|----------|
| Linux (Debian/Ubuntu) | Qt6, libsodium, curl, zlib | `sudo apt-get install -y qt6-base-dev libsodium-dev libcurl4-openssl-dev zlib1g-dev` |
| Windows (MSYS2 UCRT64) | 同上 | `pacman -S mingw-w64-ucrt-x86_64-qt6-base mingw-w64-ucrt-x86_64-libsodium mingw-w64-ucrt-x86_64-curl mingw-w64-ucrt-x86_64-zlib` |
| macOS (Homebrew) | 同上 | `brew install qt libsodium curl zlib` |

要求 C++20 编译器（GCC 10+、Clang 12+、MSVC 2019 16.11+）。

---

## 5. 构建

```bash
# 1. 克隆
git clone https://github.com/Emilianissimo/Fantom-Chat-P2P-IPv6-Chat.git
cd Fantom-Chat-P2P-IPv6-Chat

# 2. 配置 + 构建（主程序）
mkdir -p build && cd build
qmake6 ../ipv6chat.pro
make -j$(nproc)

# 3. 构建并运行单元测试
cd ../tests
mkdir -p build && cd build
qmake6 ../tests.pro
make -j$(nproc)
./FantomChatTests
```

> Windows 上把 `make` 换成 `mingw32-make`，路径与 `.pro` 文件中保持一致。

---

## 6. PR 流程

### 6.1 准备分支

```bash
git checkout main
git pull --ff-only origin main
git checkout -b feat/<short-description>      # 或 fix/<...>、docs/<...>
```

### 6.2 写代码

- **风格**：跟随文件原有风格（4 空格缩进、命名贴近 Qt 习惯：`camelCase` 函数/变量、
  `PascalCase` 类名、`UPPER_SNAKE` 宏）。
- **避免不必要重构**：只改与本次目标相关的代码，**不顺手"清理"无关代码**。
- **新增公共头文件**记得加入 `ipv6chat.pro` / `tests/tests.pri`，否则别平台构建会断。
- **不引入新依赖**：除非确有必要，并同步更新 [README.md](README.md) 的依赖清单与 CI。

### 6.3 提交规范

使用 [Conventional Commits](https://www.conventionalcommits.org/) 风格：

```
<type>(<scope>): <subject>

<body>

<footer>
```

| type | 用途 |
|------|------|
| `feat` | 新功能 |
| `fix` | Bug 修复 |
| `refactor` | 重构（不改行为） |
| `perf` | 性能改进 |
| `docs` | 文档 |
| `test` | 测试 |
| `build` | 构建/CI |
| `chore` | 杂项 |

示例：
```
feat(protocol): add file header payload codec
fix(server): skip stale socket in handshake path
docs(readme): add feedback badge
```

### 6.4 提交前自检

- [ ] `make` 在你测试的平台上构建通过
- [ ] `./FantomChatTests` 全部通过
- [ ] 新增/修改的代码有相应的测试覆盖（关键路径必加）
- [ ] 如果改了 UI 文案，确认 `*.ts` 翻译文件已经更新（`lupdate ipv6chat.pro`）
- [ ] 没有引入未声明的第三方依赖
- [ ] 没有 commit 历史里的临时调试代码（`qDebug() << "AAAAA"` 之类）
- [ ] 没有把 `config.ini`、`messages.db`、个人密钥等本地文件 commit 进来

### 6.5 创建 PR

- 标题用 Conventional Commits 格式，与最关键的 commit 对齐。
- 描述里说明 **What / Why / How / Test Plan**。
- 关联相关 Issue（`Closes #123` / `Refs #456`）。
- 推送后等待 CI（GitHub Actions 多平台矩阵构建）通过。
- 评审者会进行 Code Review，按意见迭代。**请不要 force-push**到讨论中的分支，除非评审者要求。

---

## 7. 代码结构速览

```
fantom-chat/
├── src/
│   ├── encrypting/        # 加密层（接口 + sodium 实现）
│   │   └── interfaces/    # ICryptoBackend / ICryptoSession / ICryptoError
│   ├── network/           # IPv6 P2P server/client + 多播发现
│   ├── protocol/          # Frame / FrameReader / HandshakeCodec（协议层）
│   ├── storage/           # SQLite 加密消息存储
│   ├── models/            # Qt 模型（联系人、消息列表）
│   ├── ui/                # main_window 与 delegates
│   └── utils/             # ClockSync / KeyExchange / ProtocolVersion 等
├── tests/                 # Qt Test 单元测试
├── translations/          # en / ru / zh
├── assets/                # 图片、UI 模板、QSS 样式
├── .github/workflows/     # CI 配置
└── ipv6chat.pro           # qmake 项目文件
```

---

## 8. 关于协议改动

协议层（`src/protocol/`、`src/utils/ProtocolVersion.h`、`src/utils/MessageType.h`）的改动
**必须**做到向后兼容。当前协议版本号定义在 [ProtocolVersion.h](src/utils/ProtocolVersion.h)：

- `CURRENT` = 当前实现的协议版本
- `MIN_COMPAT` = 仍能通信的最低远端版本

任何改动都需要：

1. 评估是否需要 bump `CURRENT`；
2. 在 `ProtoVer::isCompatibleWith` 中维护兼容规则；
3. 在 [tst_protocol.cpp](tests/tst_protocol.cpp) 中加入兼容性测试；
4. 在 PR 描述里写清楚"为什么这个改动不破坏旧客户端"。

---

## 9. 关于加密层改动

加密相关代码位于 `src/encrypting/`。改动原则：

- **接口优先**：所有改动都应通过 `ICryptoBackend` / `ICryptoSession` 抽象进行，
  不在调用方直接使用 libsodium 私有 API。
- **错误码**：新增错误情况请同步更新 [CryptoErrorCode.h](src/encrypting/interfaces/CryptoErrorCode.h)，
  并补充对应语言的翻译条目。
- **密钥绝不外泄**：禁止把任何密钥、随机数种子、内部状态写到 `qDebug()`。
- **测试覆盖**：所有新加密路径必须在 [tst_crypto.cpp](tests/tst_crypto.cpp) 中加入 round-trip 测试。

---

## 10. 关于 CI

CI 定义在 [.github/workflows/ci.yml](.github/workflows/ci.yml)，覆盖
Ubuntu 22.04 / Ubuntu 24.04 / Windows / macOS 矩阵构建。

- **所有 PR 必须全平台 CI 通过**才能合并。
- 如果某平台的失败与本 PR 无关（例如基础镜像问题），请在 PR 描述里说明，
  由维护者决定是否合并。

---

## 11. 版本号与发布

- 遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/) `MAJOR.MINOR.PATCH`。
- 协议版本（`ProtocolVersion.h` 中的 `CURRENT`）独立于发布版本号。
- Release 由维护者执行，使用 GitHub Actions 自动化构建多平台产物。

---

## 12. 我能贡献什么？

如果暂时不知道从何开始，可以筛选带以下标签的 Issue：

| 标签 | 含义 |
|------|------|
| `good first issue` | 适合新贡献者上手的小任务 |
| `help wanted` | 维护者希望社区帮忙的 |
| `documentation` | 文档类，无需深入读源码 |
| `bug` | 已确认的 Bug |

---

## 13. 联系

- 公开讨论：[GitHub Discussions](https://github.com/Emilianissimo/Fantom-Chat-P2P-IPv6-Chat/discussions)
- 安全问题：[Security Advisory](https://github.com/Emilianissimo/Fantom-Chat-P2P-IPv6-Chat/security/advisories/new)
- 邮件：emilerofeevskij@gmail.com

**再次感谢你的贡献！**
