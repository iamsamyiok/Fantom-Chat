<!-- 感谢你提交 PR！请按下方提示填写完整，以便评审者快速理解。 -->

## What & Why

<!-- 这个 PR 做了什么？解决了什么问题？关联 Issue 用 `Closes #xxx` / `Refs #xxx` -->

## Changes

<!-- 列出关键改动点，例如：
- 新增 `src/utils/Foo.h` 提供 xxx 能力
- 修改 `src/network/IPv6ChatServer.cpp` 修复 xxx 路径
- 同步更新 `tests/tst_xxx.cpp` 增加覆盖
-->

## Type

<!-- 勾选本次变更类型，可多选 -->

- [ ] feat       — 新功能
- [ ] fix        — Bug 修复
- [ ] refactor   — 重构（不改行为）
- [ ] perf       — 性能改进
- [ ] docs       — 文档
- [ ] test       — 测试
- [ ] build/ci   — 构建 / CI

## Checklist

<!-- 提交前自检。不适用项请保留并加 (n/a) 标注。 -->

- [ ] 我阅读过 [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] 主程序 `make` 通过
- [ ] 单元测试 `./FantomChatTests` 全部通过
- [ ] 新增 / 修改的代码有对应测试覆盖
- [ ] 涉及协议层改动时，确认 `ProtoVer::isCompatibleWith` 仍兼容旧版本，
      并在 `tst_protocol.cpp` 加入对应测试
- [ ] 涉及加密层改动时，确认所有调用通过 `ICryptoBackend` 抽象进行，
      错误码与翻译文件已同步更新
- [ ] UI 文案改动后 `lupdate ipv6chat.pro` 已刷新
- [ ] 没有把 `config.ini`、`messages.db`、本地密钥等 commit 进来
- [ ] commit message 遵循 Conventional Commits

## Test Plan

<!-- 你如何验证这次改动有效？评审者可以照着复现一遍。例如：
1. 启动两端 v1.1 与 v1.0 旧客户端，确认握手仍然成功
2. 发送一段文本，断开重连后再发，确认无丢消息
3. 运行 `./FantomChatTests` 输出全 PASS
-->

## Notes for Reviewers

<!-- 给评审者的提醒：哪些需要重点看、哪些是有意为之的设计权衡等。 -->
