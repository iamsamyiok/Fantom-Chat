# 🔒 安全策略（Security Policy）

## 报告漏洞

如果你发现 Fantom-Chat 的安全漏洞，**请勿公开 Issue**。请走以下私密流程：

1. 打开 GitHub 仓库的
   [Security Advisories](https://github.com/Emilianissimo/Fantom-Chat-P2P-IPv6-Chat/security/advisories/new)
   页面，新建一份私密报告；
2. 在报告里说明：
   - 漏洞的**影响范围**（哪些模块、是否可远程触发、是否需要已建立握手等前置条件）
   - **复现步骤**（如有 PoC 最理想）
   - 你期望的**披露时间窗口**（默认 90 天 coordinated disclosure）
3. 也可以发送加密邮件至 `emilerofeevskij@gmail.com`，PGP 公钥见仓库
   [.github/SECURITY.md#pgp](#pgp)（如未发布则以邮件回复为准）。

> 维护者承诺 **24 小时内**确认收到报告，**7 天内**给出初步评估。

---

## 支持的版本

| 版本 | 状态 | 安全更新 |
|------|------|----------|
| 最新 `main` 分支 / 最新 Release | ✅ 支持 | ✅ |
| 前一个 minor release | ⚠️ 仅关键修复 | 限严重漏洞 |
| 更老版本 | ❌ 不支持 | 请升级 |

---

## 报告时请提供

- Fantom-Chat 版本（在「关于」对话框中查看）
- 操作系统
- Qt 与 libsodium 版本
- 漏洞类型（如：握手绕过、解密失败但未断连、本地数据库明文残留等）
- 是否可复现、复现步骤、最小化 PoC

---

## 不属于安全漏洞的情况

以下情形请走普通 Issue 或 Discussion，**不要**用安全流程：

- UI 体验问题、文案错误
- 配置项默认值不够安全但用户可改
- 性能问题、资源占用高
- 协议兼容性、版本协商失败等"功能性"问题

---

## PGP

> 公钥暂未发布到仓库。如需加密通信，请先通过上述邮件索取。

---

## 致谢

感谢负责任披露的安全研究者。已修复的漏洞将在对应 Release Notes 中致谢
（如不愿留名请提前告知）。
