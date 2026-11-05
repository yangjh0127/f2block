<div align="center">

# f2block

**Watch logs. Block repeat offenders. Keep the context.**

轻量、自托管的 Linux 日志检测与永久 IP 封禁工具。

[![CI](https://github.com/yangjh0127/f2block/actions/workflows/ci.yml/badge.svg)](https://github.com/yangjh0127/f2block/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)](#快速开始)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[快速开始](#快速开始) · [使用指南](docs/operations.md) · [配置示例](config.example.json) · [贡献指南](CONTRIBUTING.md)

</div>

---

**f2block 持续读取服务日志，识别短时间内反复失败的来源，并将其加入 IPv4 / IPv6 永久黑名单。**

检测规则、黑白名单、历史记录和终端面板集中在一个工具中；地理信息通过紧凑的本地 IP 库补全。Python 部分仅使用标准库，无需安装第三方 Python 包。

```text
服务日志 → 规则匹配 → SQLite / WAL → ipset + iptables / ip6tables
                          ↕
                 本地地理库 → 联网兜底
```

## 有什么值得关注？

| 能力 | 带来的便利 |
| --- | --- |
| **直接检测日志** | SSH、Nginx 或应用日志可分别配置阈值与时间窗口，同一文件只读取一次 |
| **IPv4 + IPv6** | 使用独立的双栈集合和规则，封禁意图先落库，防火墙失败会后台对账 |
| **可追溯的管理** | 黑名单、白名单、解封原因、触发规则和历史事件都能查询 |
| **跨服务器迁移** | CSV / JSON 合并导入，保留地理字段，保护白名单与人工解封记录 |
| **小体积地理库** | 分块压缩和范围索引，按需解压；2026-11 完整样本约 **71.9 MiB** |
| **独立后台任务** | 更新库、补全地理信息和封禁处理分开运行，更新不持有封禁 / 导入操作锁 |
| **自动修复与退避** | 缺库、坏块、缺版本标记自动修复；联网限流有退避，未知结果有负缓存 |
| **命令行 + 终端面板** | 既能脚本调用，也能通过交互面板查看状态和管理名单 |

默认 SSH 规则：同一 IP 在 **1 小时内失败 3 次**即永久封禁。阈值和日志格式均可配置。

## 快速开始

适用于使用 **systemd** 的 Linux 主机。以下依赖安装命令以 Debian / Ubuntu 为例；需要 Python 3.8+、SQLite 3.24+、Bash、ipset、iptables / ip6tables 和 flock。

```bash
git clone https://github.com/yangjh0127/f2block.git
cd f2block

sudo apt-get update
sudo apt-get install python3 sqlite3 ipset iptables util-linux
sudo bash install.sh

sudo f2block doctor
sudo f2block rules list
sudo f2block
```

默认读取 `/var/log/auth.log`，安装时可选择系统已有的 `/var/log/secure`。只有 journald、没有日志文件的系统，需要先配置认证日志落盘。

安装后建议核对日志格式，并把可信的管理出口加入白名单：

```bash
# 将示例地址替换为你自己的可信出口
sudo f2block allow add 203.0.113.8 --reason "trusted management address"
sudo f2block rules test sshd --file /var/log/auth.log --lines 1000
sudo f2block status --json
```

`203.0.113.8` 是文档示例地址。预检只读取日志，不执行封禁。

## 日常操作

| 想做什么 | 命令 |
| --- | --- |
| 查看服务与防火墙状态 | `sudo f2block status` |
| 检查运行环境 | `sudo f2block doctor` |
| 打开终端面板 | `sudo f2block` |
| 查看最近 20 个封禁 IP | `sudo f2block list 20` |
| 查看 IP 详情和查询状态 | `sudo f2block info 2001:db8::7` |
| 手动解封 | `sudo f2block unban 2001:db8::7 --reason "reviewed"` |
| 查看白名单 | `sudo f2block allow list` |
| 导出黑名单 | `sudo f2block export json` |
| 预览导入 | `sudo f2block import ips.json --kind blocked` |
| 确认合并导入 | `sudo f2block import ips.json --kind blocked --yes` |
| 查看地理库和补全状态 | `sudo f2block geo status` |
| 手动更新地理库 | `sudo f2block geo update` |
| 实时查看后台日志 | `sudo f2block logs` |

手动解封后，只有新的失败事件再次达到阈值才会重新封禁。白名单会跳过后续检测。导入不会撤销白名单或人工解封，也不会恢复历史封禁计数。

## 地理信息：本地优先，未知也有状态

首次缺库时自动获取 DB-IP Lite 的 City 和 ASN 数据，构建为单个压缩文件。查询通过范围索引定位数据块，只解压命中的块，并缓存最近使用的块。

- 默认每天检查更新；丢失或损坏时提前触发修复。
- 新库在临时目录构建并逐块校验，通过后原子替换。
- 成功后清理旧地理库和构建文件，不保留地理库备份；失败保留原库。
- 定期扫描缺失字段；本地查不到时通过 IPinfo HTTPS 兜底。
- 区分未查询、已查询有结果、部分未收录、未收录、待重试与重试上限未知。
- 确定未收录的结果保存负缓存；临时失败最多实际联网重试 3 次，429 会全局退避。

2026-11 样本从 485 MiB SQLite 地理库压缩为 71.9 MiB，体积减少约 **85.2%**。大小随数据版本变化；更新的临时转换仍建议预留约 2 GB 磁盘空间。

联网兜底会向 `ipinfo.io` 发送待查询 IP，本地信息完整时不会发送。地理信息可能不完整或不准确；它用于查看来源背景，封禁由日志规则决定。

## 配置与运行边界

| 路径 | 用途 |
| --- | --- |
| `/etc/f2block/config.json` | 日志规则与运行配置 |
| `/opt/f2block/` | 已安装程序 |
| `/var/lib/f2block/f2block.db` | 名单、事件、读取位置与查询状态 |
| `/var/lib/f2block/geo/lookup.geo` | 压缩地理库 |

参考 [配置示例](config.example.json) 和 [完整使用指南](docs/operations.md)，了解自定义规则、日志轮转、迁移、升级、故障检查及卸载。

f2block 管理本机 **INPUT 入站流量**，不承担带宽型 DDoS 清洗。反向代理或 CDN 后应先确认日志记录的是可信的真实客户端 IP。永久封禁需要结合白名单和人工复核使用。

## 开发与贡献

```bash
python3 -m unittest test_geo test_enrich test_manage_features \
  test_direct_logs test_runtime test_management -v
```

测试使用隔离数据库和模拟防火墙操作，不需要连接真实服务器。欢迎通过 [Issues](https://github.com/yangjh0127/f2block/issues) 报告问题或提交改进，参与前请阅读 [贡献指南](CONTRIBUTING.md) 和 [安全报告说明](SECURITY.md)。

## 许可证与数据来源

代码使用 [Apache License 2.0](LICENSE)，版权归 f2block contributors 所有。

IP Geolocation by [DB-IP](https://db-ip.com)。运行时下载的 City Lite / ASN Lite 数据遵循 [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)，与代码许可证分开；仓库不分发地理数据库。联网兜底使用 IPinfo，相关服务受其自身条款与限额约束。
