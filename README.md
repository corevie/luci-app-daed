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

### Gist 同步（cfMac nodes.json 订阅）

ECH 页面新增 **Gist Sync** 区，把 GitHub Gist 上的 cfMac `nodes.json`
节点库作为 dae 订阅自动同步：

1. 填写 **Gist ID**（私有 Gist 再填 **GitHub Token**，需 gist 权限）、
   **文件名**（默认 nodes.json）与**订阅标签**（默认 ech_nodes）；
2. 勾选 **持久化最近一次拉取** 会使用 `gist-file://`，最近一次成功拉取
   存到 `/etc/dae/persist.d/` 作为离线回退；
3. 保存后生成 `/etc/daed/ech_sub.dae`：

```
subscription {
    ech_nodes: 'gist-file://<token>@<gistID>/nodes.json'
}
```

4. **仪表板模式**（本包）：把生成的 `echws://` 节点链接或 `gist://`
   订阅 URL 粘贴到 daed 面板的节点/订阅管理（内核已支持识别）；
   **独立 runfiles 模式**：在分组里引用 `filter: subtag(ech_nodes)`，路由
   规则即可使用这些节点（例如 `fallback: proxy`）；
5. 基础设置页开启**订阅自动更新**后，cron 会定时 `hot_reload` 重新拉取
   Gist（dae 热重载，不断连接）。

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

也支持直接在配置里手写（无需 UI）：见 `config.d/node.dae` 头部注释的
`gist://`、`gist-file://`、`file://nodes.json` 示例。

### 维护提示（与本页面相关的仓库约束）

- CI（`autoupdate.yml`）按**固定行号**改写 `daed/Makefile` 第 7/8/9/10/17
  行——请勿改动该文件前 17 行的行数。
- `/etc/init.d/luci_daed`（START=98）负责 geo 资源环境注入
  （`DAE_LOCATION_ASSET=/usr/share/v2ray`）与 resolv.conf 隔离；订阅
  定时更新 cron 由 `/etc/init.d/dae` 自行维护（`hot_reload`）。
- ECH 页面的 UCI 存于新段 `config ech 'ech'`，与 `basic.lua` 的
  `config daed 'config'` 互不干扰；ACL 已覆盖整个 `daed` UCI 配置，无需
  额外授权。

