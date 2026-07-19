# SSH Exam Gate

[English](README.md)

SSH Exam Gate 在指定的 OpenSSH 公钥登录前设置一个选择题考试。身份由请求的
Unix 账号和所提交公钥的 SHA256 指纹共同确定。密钥注释和类似邮箱的标签仅作为
元数据，不参与身份判断。

本仓库**不会**编辑、重载、重启或以其他方式更改正在运行的 `sshd`。安装二进制、
启动管理端或创建访问映射都不会自动启用拦截。只有运维人员安装并验证提供的
`Match Group` 配置后，OpenSSH 才会调用本系统。

## 架构

```text
SSH 公钥
  -> OpenSSH AuthorizedKeysCommand（%u、%f、%t、%k）
  -> ssh-exam-key-policy（只读 SQLite 策略）
     -> 待考试：受限 PTY + 强制 ssh-exam-tui 命令
     -> 已通过 Shell：注册密钥 + 正常 Shell 语义
     -> 已通过 ProxyJump：仅转发 + 精确 permitopen 目标

回环管理端 -> ssh-exam-admin -> SQLite + 原子 JSON 题库写入
```

- `ssh-exam-key-policy` 默认拒绝，仅为已启用的人员、密钥和访问映射输出
  authorized-keys 行。
- `ssh-exam-tui` 在写入尝试记录前验证 `SUDO_USER`、映射的账号/指纹/题库、
  尝试次数和通过状态。
- `ssh-exam-admin` 使用服务端渲染、CSRF 防护和双语界面，并拒绝非回环监听地址。
- SQLite 保存人员、密钥、映射、尝试记录和人员级通过状态。映射行选择题库，
  旧映射迁移后默认使用 `legacy`。
- 题库 JSON 使用同目录临时文件、同步和原子重命名写入。

为保持兼容，通过状态仍属于人员：该人员所有已启用的密钥和映射都会继承通过
结果。待考试连接使用当前访问映射选择的题库。

## 预编译发布包

版本标签会在 [GitHub Releases](https://github.com/huluhuluu/ssh-exam/releases)
发布两个文件：

- `ssh-exam-<VERSION>-linux-x86_64.tar.gz`
- `SHA256SUMS`

压缩包面向 Linux x86_64（`x86_64-unknown-linux-gnu`），包含三个已剥离符号的
二进制、示例配置/题库、部署片段、许可证和中英文 README，不包含数据库、SSH
密钥、缓存、日志或运行时数据。

解压前验证校验和：

```sh
sha256sum -c SHA256SUMS
tar -xzf ssh-exam-<VERSION>-linux-x86_64.tar.gz
```

其他架构或 glibc 基线不匹配时，请从源码构建。

## 从源码构建

使用当前稳定版 Rust 和仓库提交的依赖锁文件：

```sh
cargo test --locked
cargo build --release --locked --bins
```

发布配置启用 thin LTO、单代码生成单元、panic abort 和符号剥离。`dist/` 下的
发布二进制在普通提交中保持忽略。

发布构建后可在本地生成同样的包：

```sh
./scripts/package-release.sh \
  --version <VERSION> \
  --binary-dir target/release \
  --output-dir <OUTPUT_DIR>
```

## 安装

建议使用独立服务账号。以下账号名仅为示例，本仓库不会创建账号或组。

```text
/usr/local/libexec/ssh-exam-key-policy   root:root                  0755
/usr/local/libexec/ssh-exam-tui          root:root                  0755
/usr/local/sbin/ssh-exam-admin           root:root                  0755
/etc/ssh-exam/config.json                root:root                  0644
/etc/ssh-exam/admin-auth.json            ssh-exam-admin:root        0600
/var/lib/ssh-exam                        ssh-exam-admin:ssh-exam-db  2770
/var/lib/ssh-exam/quiz.json              ssh-exam-admin:ssh-exam-db 0640
/var/lib/ssh-exam/banks/*.json           ssh-exam-admin:ssh-exam-db 0640
/var/lib/ssh-exam/gate.db                ssh-exam-admin:ssh-exam-db 0660
```

`ssh-exam-key` 需要数据库及以后 WAL/SHM 文件的只读权限；`ssh-exam-tui` 和
`ssh-exam-admin` 需要数据库写权限。只有管理端需要题库文件及目录的创建/重命名
权限。不要授予这些账号 Docker socket 或 Docker 组权限。

复制并编辑 `examples/config.example.json`。生成部署专用的管理认证值，不要部署
示例值：

```sh
printf '%s' '<ADMIN_PASSWORD>' | /usr/local/sbin/ssh-exam-admin hash-password
openssl rand -base64 32
```

将第一项写入 `admin-auth.json` 的 `password_hash`，第二项写入
`session_secret_base64`。

启用前初始化或迁移 SQLite：

```sh
sudo -u ssh-exam-admin /usr/local/sbin/ssh-exam-admin migrate \
  --config /etc/ssh-exam/config.json
```

## 题库

`quiz_path` 必填，并始终以题库 ID `legacy` 提供。已有单文件配置无需修改。要启用
目录模式，请将 `quiz_directory` 设置为绝对目录。目录中安全的 `*.json` 文件名
主干就是稳定题库 ID，例如 `host-ssh.json` 对应 `host-ssh`。

题库 ID 长度为 1-64，只能使用小写字母、数字和内部单个短横线；`legacy` 为保留
值。每个题库包含：

- 标题；
- 描述性环境：`host`、`docker`、`network` 或 `general`；
- 通过分数和最大尝试次数；
- 至少一道选择题。

管理端 Exam 页面可列出/选择/创建题库、编辑设置以及增删改问题，并拒绝删除最后
一道问题。

`tui_language` 可设为 `en`、`zh` 或 `bilingual`，默认双语。TUI 只本地化门禁状态
和操作提示，不会翻译题库中编写的标题、问题或选项。

`examples/banks/` 中的小型题库仅用于教学。环境元数据不会执行命令、配置主机、
创建网络、访问 Docker 或启动容器。

## 管理隧道

管理端只监听回环地址（默认 `127.0.0.1:8787`）。通过提供的 unit 或前台方式启动
后，使用堡垒机实际 SSH 监听端口创建本地隧道：

```sh
ssh -p <SSH_PORT> -L 8787:127.0.0.1:8787 \
  recovery-admin@bastion.example.org
```

打开 `http://127.0.0.1:8787/`。语言选择器完全由服务端渲染，无需 JavaScript。
成功消息使用签名的一次性 flash cookie，因此页面 URL 保持为 `/`、`/people` 和
`/exam/<BANK_ID>`。

在 People 页面创建人员、注册每个设备公钥并添加访问映射；在 Exam 页面管理
兼容题目和目录题库。

## 访问映射

访问映射将人员或指定设备密钥关联到：

- 现有 Unix 登录账号；
- `Normal shell` 或仅转发的 `Shared ProxyJump`；
- 一个题库；
- Shared ProxyJump 的精确转发目标。

映射**不会**配置 SSH 监听端口。允许目标中的端口是目标服务端口。普通 Shell 的
Unix 账号专属于一个人员；Shared ProxyJump 账号可以复用，但禁止通配目标。

## SSH 拦截与任意端口

本系统与端口无关。`deploy/sshd_config.snippet` 不包含 `Port` 或
`ListenAddress`。OpenSSH 将 `%u`（账号）、`%f`（指纹）、`%t`（密钥类型）和
`%k`（base64 密钥数据）传给 `AuthorizedKeysCommand`。策略程序验证这些值和已
注册密钥材料后才输出结果。

待考试时输出 `restrict,pty` 和包含已验证题库/语言的强制 TUI 命令；通过后输出
普通 Shell 的注册密钥，或带精确 `permitopen` 的仅转发选项。

示例核心配置为：

```text
Match Group ssh-exam-gated
    AuthorizedKeysFile none
    AuthorizedKeysCommand /usr/local/libexec/ssh-exam-key-policy --config /etc/ssh-exam/config.json --username %u --fingerprint %f --key-type %t --key-base64 %k
    AuthorizedKeysCommandUser ssh-exam-key
```

至少保留一个经过验证且不属于 `ssh-exam-gated` 的恢复账号。

## 隔离测试

修改生产配置前使用 `scripts/isolated-sshd.sh`。它只在调用者指定目录下写入，要求
显式提供未占用端口，不读取/编辑实时 `sshd_config`，也不重载系统 SSH。

测试 Unix 账号必须已存在，并在配置数据库中拥有注册密钥和访问映射。

```sh
./scripts/isolated-sshd.sh dry-run \
  --runtime-dir <RUNTIME_DIR> \
  --port <TEST_PORT> \
  --test-user exam-test \
  --app-config /etc/ssh-exam/config.json \
  --policy-binary /usr/local/libexec/ssh-exam-key-policy \
  --command-user ssh-exam-key

sudo ./scripts/isolated-sshd.sh validate \
  --runtime-dir <RUNTIME_DIR> --port <TEST_PORT> \
  --test-user exam-test \
  --app-config /etc/ssh-exam/config.json \
  --policy-binary /usr/local/libexec/ssh-exam-key-policy \
  --command-user ssh-exam-key

sudo ./scripts/isolated-sshd.sh background \
  --runtime-dir <RUNTIME_DIR> --port <TEST_PORT> \
  --test-user exam-test \
  --app-config /etc/ssh-exam/config.json \
  --policy-binary /usr/local/libexec/ssh-exam-key-policy \
  --command-user ssh-exam-key
```

使用真实 PTY 完成首次考试，然后仅停止并清理该隔离实例：

```sh
ssh -p <TEST_PORT> -t exam-test@127.0.0.1
sudo ./scripts/isolated-sshd.sh stop --runtime-dir <RUNTIME_DIR>
sudo ./scripts/isolated-sshd.sh cleanup --runtime-dir <RUNTIME_DIR>
```

只在明确隔离的监听器上使用 `--listen-address`。防火墙规则和容器端口发布仍由外部
部署系统负责。

## 生产启用

1. 保持一个已验证的恢复会话，并在实际 `<SSH_PORT>` 上验证第二个恢复登录。恢复
   账号不能加入门禁组。
2. 安装二进制、配置、状态目录、服务身份、数据库权限和审查后的 sudoers 规则，
   用 `visudo -cf deploy/sudoers.snippet` 验证。
3. 启动回环管理端，注册一次性测试人员/密钥/映射并验证题库编辑。
4. 使用相同应用配置完成上述隔离测试流程。
5. 只将预期账号加入 `ssh-exam-gated`，安装审查后的 `Match Group` 片段。启用门禁
   时不要添加或修改 `Port`。
6. 用 `/usr/sbin/sshd -t` 验证完整生产配置，并用
   `sshd -T -C user=<ACCOUNT>,host=bastion.example.org,addr=<CLIENT_IP>` 检查匹配结果。
7. 重载而不是重启系统 SSH。从新终端先测试恢复账号，再测试一次性门禁账号；
   全程保留原恢复会话。

本仓库不会自动执行任何实时启用步骤。

## 首次考试与 VS Code

首次考试必须使用真实 PTY 终端：

```sh
ssh -p <SSH_PORT> -t person-account@bastion.example.org
# 完成考试，连接会结束。
ssh -p <SSH_PORT> person-account@bastion.example.org
```

VS Code Remote-SSH 通常启动非 PTY exec channel，**不应**期望它显示本 TUI。请先在
真实终端中使用 `ssh -t` 完成考试。通过后，普通 VS Code Remote-SSH 连接会按映射
的 Shell 或转发语义正常工作。

ProxyJump 也应先直接使用 `ssh -t` 完成考试，再在堡垒机配置项中设置实际
`Port <SSH_PORT>` 并作为跳板使用。

## 故障排查

- **直接出现普通 Shell 而非考试：**该连接的 `AuthorizedKeysCommand` 未生效，
  或 Unix 用户/密钥未注册到已启用的访问映射（也可能人员已通过）。检查有效的
  `Match Group`、`%u/%f/%t/%k` 调用、组成员、映射、密钥指纹和通过状态。
- **密钥被拒绝：**比较 `ssh-keygen -lf <PUBLIC_KEY_FILE>` 与注册指纹。注释和邮箱
  不标识密钥。
- **端口错误：**映射不会选择监听器。检查有效 `Port`/`ListenAddress`、防火墙或
  容器发布，并使用实际 `-p <SSH_PORT>`。
- **VS Code 或 ProxyJump 不显示 TUI：**先直接使用 `ssh -t`；这些流程通常使用
  非 PTY channel。
- **管理端不可达：**保持回环监听并使用本地隧道。
- **题库写入错误：**管理端需要常规题库文件的写权限，以及父目录/题库目录的
  创建和重命名权限；符号链接会被拒绝。

## 回滚

从仍打开的恢复会话中，将受影响用户移出 `ssh-exam-gated`，或删除/注释门禁
`Match` 块。用 `sshd -t` 验证完整配置后重载 SSH。当匹配不再生效时，保留的
`AuthorizedKeysFile` 访问恢复。恢复访问期间可保留数据库和二进制。

## 验证

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
cargo build --release --locked --bins
./scripts/validate-sshd.sh
visudo -cf deploy/sudoers.snippet
```

`scripts/pty-smoke.py` 验证 TUI 启动、调整大小、输入和清理。
`scripts/benchmark-key-policy.py` 输出预热后的进程中位数和 p95，目标为中位数低于
20 ms、p95 低于 50 ms。
