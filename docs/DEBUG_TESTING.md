# SDK Debug 自测（开发阶段，非正式 Release）

本仓库仅输出用于验证 SDK 的 `p2p-sdk-debug`，没有上传/下载文件等 Transfer 业务。

## GitHub Actions Debug 下载

工作流 `SDK debug binaries (five platforms)` 对每种平台原生执行 `cargo build` 和 `selftest`，测试成功才上传对应可执行文件；到 PR 的 Checks 或 Actions 运行详情，在 Artifacts 中下载。

| 平台 | 文件名 |
| --- | --- |
| Windows x86_64 | `p2p-sdk-debug-windows-x86_64` |
| macOS Intel x86_64 | `p2p-sdk-debug-macos-x86_64` |
| macOS Apple Silicon arm64 | `p2p-sdk-debug-macos-aarch64` |
| Linux x86_64 | `p2p-sdk-debug-linux-x86_64` |
| Linux arm64 | `p2p-sdk-debug-linux-aarch64` |

运行命令：`./p2p-sdk-debug selftest`（Windows `p2p-sdk-debug.exe selftest`）。

`selftest` 在本机创建两个真实 UDP Owner，执行标准 ICE 双端 STUN 认证、提名，同一端口上创建两个独立 TLS QUIC Connection 并运行 Control/Data Stream Echo。只有所有检查成功才返回 0。

`./p2p-sdk-debug stun 1.2.3.4:3478` 可选，查询指定 STUN 地址（仅限 IP，IPv6 `[地址]:3478`），该命令的 Socket 映射**不是**已经通过 ICE 提名的 QUIC UDP 路径；不能用于证明 NAT 穿透成功。公开 STUN 地址需要你自行选择，避免持续重试。

**限制**：这不是两台机器之间的 INVITE/REPLY 连接工具；不会宣称测试了公网 NAT/IPv6 状态防火墙或多网卡候选。后续将加入真正双机手动信令和完整经身份确认的 QUIC 会话，再邀请用户手工验证。运行日志应脱敏，勿发送连接码、密码或完整 IP/设备隐私信息。
