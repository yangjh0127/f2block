# f2block — 本地日志检测与永久 IP 封禁

直接持续读取服务器日志，按可配置规则统计失败事件，在时间窗口内达到阈值后永久封禁来源 IPv4/IPv6。不依赖 Fail2Ban，也不调用它的客户端或修改它的配置。

链路：`服务日志 → 规则匹配 → 按规则和 IP 统计 → SQLite 记录 → ipset + iptables/ip6tables DROP`。

## 安装与升级

Linux 需要 Python 3.8+、SQLite 3.24+、Bash、ipset、iptables/ip6tables、flock 和 systemd：

```bash
sudo apt-get install python3 sqlite3 ipset iptables util-linux
sudo bash install.sh
sudo f2block rules list
sudo f2block doctor
sudo f2block
```

安装器生成 `/etc/f2block/config.json`。默认监控 `/var/log/auth.log` 中的 SSH 登录失败：一小时（3600 秒）内同一 IP 失败 3 次即永久封禁。安装时如果只有 `/var/log/secure`，会选择该路径。仅使用 journald、没有日志文件的系统需先配置服务将日志落盘；本版直接监控文件，不订阅 journal。

修改规则后运行 `sudo f2block service restart`。程序位于 `/opt/f2block/`，数据库和锁位于 `/var/lib/f2block/`。升级保留已有黑名单、白名单和历史，并在数据目录的 `backups/` 备份数据库、程序和旧配置。

旧配置未提供 `rules` 时，安装器为 `log_file` 生成 SSH 规则；旧的 `/var/log/fail2ban.log` 会改为系统认证日志。旧的 `jail_config` 字段仍可读取但不再使用。后台不会投递旧的 Fail2Ban 待重试任务，也不会改动 Fail2Ban 的运行状态；如果服务器仍运行 Fail2Ban，它自己的封禁需单独管理。

从旧目录迁移请使用 `sudo bash install.sh --migrate-from /root/.f2block`；目标已有数据库时拒绝覆盖。仓库不包含运行数据库或服务器记录。

## 多日志规则

[config.example.json](../config.example.json) 含默认 SSH 规则和一条默认关闭的 Nginx 401 规则。可按实际日志格式添加规则；同一文件可以配置多条规则，每个文件只读取一次。

```json
{
  "data_dir": "/var/lib/f2block",
  "sync_interval": 30,
  "geo_enabled": true,
  "start_at_end": true,
  "rules": [
    {
      "name": "app-login",
      "log_file": "/var/log/myapp/security.log",
      "pattern": "^(?P<time>[^ ]+) login_failed ip=(?P<ip>[^ ]+)$",
      "time_format": "auto",
      "find_time": 300,
      "max_retry": 10
    }
  ]
}
```

以上规则适配形如 `2026-10-29T10:20:30+08:00 login_failed ip=2001:db8::7` 的日志，在 300 秒内累计 10 次失败后封禁。它是配置示例，实际应用必须使用自身日志格式。

| 字段 | 含义 |
| --- | --- |
| `name` | 唯一规则名，字母、数字、下划线或短横线，最多 64 字符 |
| `log_file` | 日志文件的绝对路径 |
| `pattern` | Python 正则表达式，必须含 `(?P<ip>...)` 和 `(?P<time>...)` 命名组 |
| `max_retry` | 时间窗口内触发封禁的次数，1–100000 |
| `find_time` | 统计窗口秒数，1–604800 |
| `time_format` | 默认 `auto`；也可填 `unix` 或 `datetime.strptime` 格式 |
| `enabled` | 默认 `true`，至少启用一条规则 |

`auto` 支持 ISO 8601 和 SSH 常见的 `Oct 29 10:20:30` 时间；无年份的时间按最接近当前时间的年份解释。日志时间必须在统计窗口内；超过当前时间 5 秒以上的事件被忽略。使用其他格式时显式设置 `time_format`。主机时钟和服务日志时间应一致。

Nginx 示例对应官方 [combined 日志格式](https://nginx.org/en/docs/http/ngx_http_log_module.html#log_format)，仅统计 401，默认禁用；不要把所有 4xx 一概作为攻击。启用前核对真实客户端 IP：反向代理/CDN 后的日志可能记录代理地址，应先配置可信代理范围；不要直接信任客户端自行提供的转发头。

正则应锚定服务名、结构和真实客户端字段，避免从用户名、请求路径或 User-Agent 中捕获攻击者伪造的 IP。规则来自管理员配置，正则在本进程执行，应避免产生灾难性回溯的表达式。

## 启用前预检

```bash
sudo f2block rules list
sudo f2block rules test sshd --file /var/log/auth.log --lines 1000
sudo f2block service restart
sudo f2block doctor
```

`rules test` 只读取指定文件的前 N 行，显示匹配 IP、日志时间和解析错误，不写数据库、不执行封禁。它检查匹配效果，不模拟实时窗口计数。未匹配不会自动视为配置错误，请同时用真实失败日志和正常日志核验。

首次发现一个新日志源时默认从文件末尾开始，避免把既有历史作为新攻击；后续从持久化位置续读，轮转后的新文件从头读取。需要回放时可设置 `start_at_end: false`，此选项只作用于尚无读取位置的新日志源，仍受日志时间窗口限制。重命名轮转与检测到的 copytruncate 支持续读；如果文件在两次检查之间截断并增长到超过旧位置，单靠文件轮询无法识别这次截断，应优先使用重命名轮转。

规则计数和日志位置保存在 SQLite，重启后继续统计；同一文件位置重读不会重复计数。修改规则配置会启用新的独立计数。每个日志源独立轮询，一个文件缺失或不可读不会阻塞其他源，错误在 `status` / `doctor` 中显示。程序运行期间可读取仍打开的旧轮转文件；重启后不会主动搜寻历史轮转文件。

## 管理命令

```bash
sudo f2block status --json
sudo f2block logs
sudo f2block list 20
sudo f2block info 2001:db8::7
sudo f2block events 100 --ip 2001:db8::7
sudo f2block history 100
sudo f2block unban 2001:db8::7 --reason "误封"
sudo f2block allow add 203.0.113.8 --reason "管理出口"
sudo f2block allow list
sudo f2block allow remove 203.0.113.8
sudo f2block sync --dry-run
sudo f2block sync
sudo f2block dashboard
sudo f2block export json
sudo f2block import /root/ips.csv --kind blocked
sudo f2block import /root/ips.csv --kind blocked --yes
sudo f2block service restart
```

白名单立即解除本工具的封禁，并跳过后续匹配。`unban` 清除既有统计和当前封禁；只有解封之后的新失败事件重新达到阈值才会封禁。移除白名单后也从新的失败事件开始统计。操作原因以参数化 SQL 保存，不经 shell 拼接。

黑名单导入合并 IP，并保留文件中的 `country`、`region`、`city`、`org` 地理字段。已有记录仅补齐 NULL、空白或 Unknown 字段，保留已有有效地理信息；不恢复或覆盖历史、封禁时间和计数。跳过白名单和人工解封地址，导入后的同步不会把无关 ipset 成员引入数据库。显式执行 `sync` 会补全防火墙孤儿记录。CSV 需有 `ip` 表头，JSON 使用 `[{"ip":"2001:db8::7"}]`，也兼容仅包含 IP 的旧文件；每次最多 10000 条，先完整校验再写入。曾导入丢失地理信息的记录，可升级后重新导入原导出文件来补齐，无需删除现有黑名单。

IPv4 使用 `f2block` 集合（`family inet`）和 `iptables`；IPv6 使用 `f2block6` 集合（`family inet6`）和 `ip6tables`。仅支持不含网段掩码和接口区域标识的单个地址。防火墙执行失败时先保留封禁意图，后台对账会重试，不重复增加封禁次数。

历史表中的 `jail` 列继续保留以兼容旧记录；直接检测产生的新记录在该列保存规则名，`f2block jail NAME` / `list --jail NAME` 可按规则过滤。`detection_bans` 表另存触发时的匹配次数、阈值和窗口；过期的窗口计数由后台清理。

`sudo f2block uninstall --yes` 卸载程序和服务，保留数据、配置与现有封禁。保护范围为本机 INPUT 入站流量，不承担带宽型 DDoS 清洗。

## 验证

仅需 Python 标准库，运行维护中的回归测试：

```bash
python3 -m unittest test_geo test_enrich test_manage_features test_direct_logs test_runtime test_management -v
```

这些测试覆盖规则检测、管理操作、双栈处理、文件交换、库修复、联网退避、负缓存与并发隔离。防火墙命令在单元测试中以模拟对象或测试夹具替代；生产环境还需运行 `sudo f2block doctor` 核验实际 Linux 内核规则。

## 本地 IP 地理信息与容错

仅使用 Python 标准库。主地理库为数据目录下的 `geo/lookup.geo`：单文件包含分块 zlib 数据和未压缩 IP 范围索引，按索引只读取、解压命中的块，缓存最近 8 个解压块。City、ASN 与 IPv4、IPv6 在同一文件原子发布，避免多文件版本不一致。2026 年 11 月完整库约 71.9 MiB，比原 SQLite 库减少 85.2%。

首次缺库时自动下载 DB-IP 官方 City Lite、ASN Lite CSV。旧版 SQLite 地理库会自动转换，无需重新下载。更新先在临时目录构建、逐块验证，再原子替换；成功后移除旧地理库和临时文件，不保留地理库备份。下载、磁盘空间不足、构建或校验失败时保留原库。主黑名单数据库 `f2block.db` 不会被替换或清理。

库维护、地理信息补全和封禁处理分别运行。更新线程不持有封禁/导入的操作锁；更新期间继续查询旧库。默认每天检查库更新并逐块审计，可配置 `geo_update_interval`（3600–2678400 秒）。缺库、缺标记或查询发现损坏块时立即安排修复，不等定期更新；失败退避重试，不循环请求下载。丢失的 `release.json` 从库内元数据恢复，无需重新下载。下一次更新会清理本程序遗留的构建文件。

补全线程每隔约 5 秒扫描缺失的国家、省份、城市或组织字段，兼容 NULL、空白和 Unknown；已有有效字段不覆盖。本地库缺失字段时使用 IPinfo HTTPS 联网兜底，单次超时 3 秒、全局请求间隔至少 5 秒；429 遵守 Retry-After 并至少退避一小时。暂时失败每个 IP 最多实际请求 3 次，冷却期跨重启保留。

查询状态持久化区分：未查询、有结果、部分字段未收录、已查询未收录、临时失败待重试和重试上限未知。确定未收录及部分未收录的结果保存负缓存，同一库版本不重复联网查询；新库版本只重新进行本地匹配。重新封禁的新记录和重新导入补齐的记录可以重新匹配。省份等本身未收录的字段保留 Unknown，不伪造数据。

```bash
sudo f2block geo status
sudo f2block geo update
sudo f2block info 8.8.8.8
sudo f2block doctor
```

手动 `geo update` 强制下载更新，后台自动加载新文件。首次获取和更新需访问 `download.db-ip.com`；联网兜底会将待查询 IP 发送给 `ipinfo.io`，本地命中完整信息时不发送。更新临时转换仍需额外磁盘空间，建议预留 2 GB。

IP Geolocation by [DB-IP](https://db-ip.com)，City Lite 和 ASN Lite 数据使用 [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) 许可，详见 [数据库说明](https://db-ip.com/db/lite.php)。
