<h1 align="center">luci-app-daed</h1>
<p align="center">
  <img width="100" src="https://github.com/corevie/dae/blob/main/logo.png?raw=true" />
</p>
<p align="center">
  <b>一个基于 eBPF 的高性能透明代理解决方案。</b>
</p>

---

## 构建说明（dae-wing 已恢复，构建在本地 corevie/dae 内核上）

本仓库的 `daed` 包构建 **dae-wing**（daed 仪表板守护进程，`/usr/bin/daed`），
其 dae 内核使用本地 vendored 的 corevie/dae 源码（含 ech-workers ECH 隧道、
cfMac nodes.json 订阅适配与 GitHub Gist 同步）：

- `daed/dae-core/` —— corevie/dae 完整源码快照；
- `daed/dae-kern-headers/` —— eBPF 头文件快照（构建时装入 kern/headers）；
- `patchset/build_fixes.patch` —— 构建时应用到 dae-wing。

构建时对 dae-wing 源码做的适配（已在 dc50308 上验证）：
1. `github.com/daeuniverse/dae` → `github.com/corevie/dae`（保留
   dae-config-dist 依赖与 wing 自身 module 路径）；
2. go.mod 增加 `replace github.com/corevie/dae => ./dae-core`；
3. 合并 core 的 go.sum 条目（避免 go mod tidy 拉入测试依赖）。

升级本地 dae-core 时，把新版源码同步到 `daed/dae-core/`（排除 `.git`、
生成的 `bpf_bpf*.go`、`kern/headers/`）后重新编译即可。

## 快速入门

### 1. 环境准备 (编译主机)

在编译之前，请确保您的编译主机已安装必要的开发工具。参考 [apt.llvm.org](https://apt.llvm.org/) 安装最新版本的 Clang 和 LLVM。

```bash
apt-get update
apt-get install -y clang llvm npm
npm install -g pnpm
```

### 2. 获取源码

进入您的 OpenWrt 目录，克隆本仓库到 `package` 目录：

```bash
git clone https://github.com/QiuSimons/luci-app-daed package/dae
```

### 3. 内核配置要求 (DAE 运行前提)

DAE 依赖 eBPF 和 BTF。请在 `.config` 中添加以下内核配置以启用相关支持：

```makefile
CONFIG_DEVEL=y
CONFIG_KERNEL_DEBUG_INFO=y
CONFIG_KERNEL_DEBUG_INFO_REDUCED=n
CONFIG_KERNEL_DEBUG_INFO_BTF=y
CONFIG_KERNEL_CGROUPS=y
CONFIG_KERNEL_CGROUP_BPF=y
CONFIG_KERNEL_BPF_EVENTS=y
CONFIG_BPF_TOOLCHAIN_HOST=y
CONFIG_KERNEL_XDP_SOCKETS=y
CONFIG_PACKAGE_kmod-xdp-sockets-diag=y
```

### 4. 编译与安装

```bash
make menuconfig # 路径: LUCI -> Applications -> luci-app-daed
make package/dae/luci-app-daed/compile V=s
```

---

## 核心概念：BTF 与 CO-RE

### BTF 来源选择

在 `make menuconfig` 中，您可以根据内核支持情况选择 BTF 来源：

- **Use kernel BTF (integrated)**: **[推荐]** 要求内核开启 `CONFIG_KERNEL_DEBUG_INFO_BTF=y`。
- **Use vmlinux-btf package**: 如果内核不支持原生 BTF，可选择此项以使用外部 [vmlinux-btf](https://github.com/QiuSimons/vmlinux-btf) 软件包。

### vmlinux-btf 依赖说明

由于预编译安装包无法自动探测内核是否支持 BTF，为了确保稳定性，程序默认依赖 `vmlinux-btf`。

- **方案 A：手动补全依赖 (推荐)**
  如果软件源缺失该包，请前往 [opkg.cooluc.com](https://opkg.cooluc.com/) 下载。
  - **建议**: 优先选择与内核版本号 (`x.y.z`) 完全一致的包；至少保证主次版本号 (`x.y`) 一致。
- **方案 B：忽略依赖 (高级用户)**
  如果您确认内核已原生支持 BTF (`CONFIG_KERNEL_DEBUG_INFO_BTF=y`)，可在安装时使用 `--force-depends` 参数忽略依赖检查。

---

## ECH 隧道（ech-workers）

LuCI 应用内置 **ECH Tunnel** 页面（服务 → DAED → ECH Tunnel），用于配置
dae-2.0.0 中集成的 ech-workers 隧道客户端（TLS 1.3 Encrypted Client Hello
的 wss 隧道）。

页面选项与 dae 配置的对应关系：

| UI 选项 | UCI（`/etc/config/daed` 段 `ech`） | 生成的 dae 配置 |
|---|---|---|
| 启用 | `ech.enabled` | 生成/删除运行文件并重启守护进程 |
| 隧道服务器 | `ech.server` | `ech_tunnel.server`（`host:port[/path]`） |
| 本地代理监听地址 | `ech.listen` | `ech_tunnel.listen`（SOCKS5/HTTP 共用端口） |
| 固定服务器 IP | `ech.ip` | `ech_tunnel.ip` |
| 认证令牌 | `ech.token` | `ech_tunnel.token`（websocket 子协议） |
| ECH 配置 DoH 服务器 | `ech.dns` | `ech_tunnel.dns` |
| ECH 配置域名 | `ech.ech_domain` | `ech_tunnel.ech_domain` |
| 同时生成 echws:// 节点 | `ech.gen_node` | 额外写入 `node`/`group` 段 |
| 运行文件路径 | `ech.config_file` | 片段写入位置（默认 `/etc/daed/ech_tunnel.dae`） |

行为说明：

- **保存并应用**后，页面会重新生成运行文件（权限 600，满足 dae 对配置
  文件权限的要求）并重启守护进程。
- 生成的片段是 include 友好的：不含 `global`/`routing` 段，可被主配置的
  `include { ... }` 合并；daed（配置目录模式）直接读取配置目录。
- 勾选 **同时生成 echws:// 节点** 后，路由规则可以直接使用出站
  `ech_tunnel`（例如 `fallback: ech_tunnel`）。
- 页面顶部的状态面板每 5 秒刷新：运行文件是否生成、本地代理端口是否
  监听、守护进程是否运行。
- 校验：服务器/监听地址必须是 `host:port[/path]` 格式（IPv6 需括号），
  端口范围 1-65535，IP 必须合法，运行文件路径必须为绝对路径。

### Gist 同步（cfMac nodes.json）

ECH 页面的 **Gist Sync** 区把 GitHub Gist 上的 cfMac `nodes.json` 节点库
导入到守护进程的节点列表。**仪表板构建（本包）不读取 `*.dae` 订阅**，所以
同步走的是守护进程启动时扫描的投递目录 `/etc/daed/nodes.d/`：

1. 填写 **Gist ID**（私有 Gist 再填 **GitHub Token**，需 gist 权限）、
   **文件名**（默认 `nodes.json`）与**订阅标签**（默认 `ech_nodes`，即投递
   文件名）；
2. 勾选 **启用 Gist 同步** 后，`/etc/init.d/luci_daed` 会写入一条 cron：
   按**基础设置**页的更新时间/周期执行 `/usr/libexec/daed-gist-sync`；
3. 该脚本与页面上的**下载**按钮调用**同一份代码**
   （`luci.model.daed_gist`）：拉取 Gist → 校验 → 原子写入
   `/etc/daed/nodes.d/<标签>.json`（权限 600）→ 内容变化时重启 daed；
4. 守护进程下次启动时导入投递文件（见下节）。

### 一键下载节点（Download & Update Nodes）

**下载** 按钮立即执行一次上述流程：

1. 用表单里的 Gist ID / 令牌 / 文件名即时拉取 Gist（`api.github.com`，私有
   Gist 带 `Authorization: Bearer`；大文件回退 `raw_url`）；
2. 校验内容并识别格式：**cfMac nodes.json**、**SIP008**、**base64 订阅**或
   **链接列表**——与守护进程支持的格式一致（HTML 页面、GitHub 错误 JSON 等
   会被拒绝，避免覆盖已有节点）；
3. **覆盖**写入 `/etc/daed/nodes.d/<标签>.json`（先写 `.tmp` 再 `mv`，守护
   进程不会读到半截文件；权限 600）；内容与现有文件一致时**不重启** daed；
4. 重启 daed —— 守护进程启动时扫描该目录（dae-wing 已打补丁支持）：

   - 每个 `<tag>.json` / `<tag>.txt` 变成一个**订阅**（标签 = 文件名）；
   - 内容按 cfMac nodes.json / SIP008 / base64 / 明文链接列表解析，每个条目
     转成一个 `echws://` 节点，**节点名取自 nodes.json 的 `name` 字段**；
   - 同名**分组**自动创建（`min_moving_avg` 策略）并绑定该订阅；
   - 之后在 daed 面板的 **订阅 / 节点 / 分组** 列表里即可看到这些节点，
     在路由配置里引用该分组（如 `fallback: ech_nodes`）即可供服务使用。

按钮会即时反馈结果（成功：格式、节点数与名称预览、是否变化；失败：具体原因）。

**导入结果回授**：守护进程每次启动会把每个投递文件的处理结果写入
`/tmp/daed-nodes-sync.json`，ECH 页面的状态面板据此显示：

| 状态 | 含义 |
|---|---|
| 等待守护进程导入 | 文件已写入，daed 尚未重启扫描 |
| 已导入 N 个节点 | 订阅建立成功 |
| 已跳过 | 该标签已被另一个订阅占用（守护进程不会抢占，也不导入） |
| 文件不可用 / 导入失败 | 标签非法或解析失败，附原因 |
| 保留 M 个旧节点 | 这些节点已不在源里，但因被手工固定到分组而保留 |

面板同时列出所有投递文件（不只当前标签），因此改了标签但没保存也不会看错。

**字段映射**（cfMac 节点 → echws:// 出站）：

| nodes.json | echws:// | 说明 |
|---|---|---|
| `wssAddr` | `host:port/path` | 末尾 `?ip=` 装饰剥离为候选 IP |
| `prefIp` | `ip=`（优先） | 测速优选 IP，多值逗号分隔 |
| `wssAddr` 内嵌 `?ip=` | `ip=`（追加去重） | Cloudflare 边缘候选 |
| `token` | `token=` | websocket 子协议 |
| `echDns` | `dns=` | ECH 配置 DoH 服务器 |
| `echDomain` | `ech=` | ECH HTTPS 记录域名 |
| `name` | `#fragment` | 节点名（支持中文） |

多 IP 采用**随机起点轮询**：每条连接从随机偏移的候选开始，重试自动
切换到下一个，配合 dae 的 `min_moving_avg` 策略实现节点内故障转移。

也支持直接手写投递文件（无需 UI）：在 `/etc/daed/nodes.d/` 放
`<标签>.json`（cfMac nodes.json）或 `<标签>.txt`（每行一个链接，`#` 开头为
注释），重启 daed 即可。

### 维护提示（与本页面相关的仓库约束）

- CI（`autoupdate.yml`）按**固定行号**改写 `daed/Makefile` 第 7/8/9/10/17
  行——请勿改动该文件前 17 行的行数。
- `/etc/init.d/luci_daed`（START=98）负责 geo 资源环境注入
  （`DAE_LOCATION_ASSET=/usr/share/v2ray`）与 resolv.conf 隔离；订阅
  定时更新 cron 由 `/etc/init.d/luci_daed` 维护（`daed restart`）。
- ECH 页面的 UCI 存于新段 `config ech 'ech'`，与 `basic.lua` 的
  `config daed 'config'` 互不干扰；rpcd ACL 覆盖整个 `daed` UCI 配置。
  文件编辑器与 gist 下载只能写白名单路径（`/etc/daed` 下的 `.dae` 与
  `/etc/daed/nodes.d/<tag>.json`）。
- **主机侧测试**：`test_controller.lua`、`test_ech_download.lua`、
  `test_ech_lua.lua`、`test_gist_sync_script.lua`、`test_paths_contract.lua`、
  `test_luci_daed_cron.sh` 全部可在开发机上运行（`lua <file>` /
  `sh <file>`），共用 `test_support.lua` 里的真实 JSON 解析器。
  `test_paths_contract.lua` 专门盯住跨语言约定（投递目录、报告路径、
  脚本路径），这类漂移正是此前功能静默失效的原因。
- **数据源说明**：仪表板模式下 wing.db 是节点/订阅/路由的权威数据源。
  daemon 以空配置启动核心、随后由 DB 生成配置（`dae.ParseConfig` 只拼接
  `global`/`dns`/`routing` 三段），因此 runfile 里的
  `global`/`routing`/`subscription` 等段**不会**进入核心配置：
  - 节点/订阅走 `nodes.d/` 投递（见上）；
  - `ech_tunnel` 段**例外**：daemon 每次加载配置时会合并 `/etc/daed/*.dae`
    中的该段（补丁 `MergeEchTunnelFragments`），因此 ECH 隧道页生成的
    `ech_tunnel.dae` 在仪表板构建中同样生效。只读取 `ech_tunnel` 一段，
    片段里若混入 `global`/`routing` 不会覆盖仪表板；片段被组/其他用户可写
    （权限 & 0037）时拒绝加载并在日志中说明。**运行文件路径必须位于
    `/etc/daed/` 内**，否则只有独立 dae 构建会读取（状态面板会给出提示）。
- **补丁漂移防护**：`patchset/` 针对 Makefile 中固定的 dae-wing 版本，
  构建时会用 `VerifyLocalNodesPatch` 校验补丁后的关键符号，补丁失配即
  **中止构建**（此前用 `|| true` 会静默产出没有导入功能的固件）。
  `patchset/tests/` 下是投递导入与 ech_tunnel 片段的行为测试
  （`wing-local-nodes_test.go`、`wing-ech-tunnel-fragments_test.go`），
  升级 wing 后请按文件头注释运行一遍。
- **本地节点清理**：daemon 启动时会清除 `nodes.d/` 中已不存在的文件对应的
  订阅与自动创建的分组，避免 Dashboard 出现僵尸订阅。
- **日志路径**：Logs 页读取 `/var/log/daed/daed.log`，与 `/etc/init.d/daed`
  的 `--logfile` 保持一致。
- **Token 安全**：Gist Token 以明文存在于 `/etc/config/daed`；拉取到的节点
  链接（内含隧道令牌）存于 `/etc/daed/nodes.d/<tag>.json`（权限 600）。
  请使用低权限、仅限 gist 的 Token。
