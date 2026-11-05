"""Curses dashboard. No dependencies beyond Python's Linux standard library."""
import locale
import sqlite3
import time
import unicodedata

from f2block_cli import clean, describe, health, operate


def fit(value, width):
    output, used = '', 0
    for char in clean(value):
        size = 0 if unicodedata.combining(char) else 2 if unicodedata.east_asian_width(char) in 'WF' else 1
        if used + size > width:
            break
        output += char
        used += size
    return output


def launch(config, store):
    try:
        import curses
    except ImportError:
        print('当前 Python 没有 curses 支持，请使用 f2block list / info / status。')
        return 1
    locale.setlocale(locale.LC_ALL, '')

    def session(screen):
        curses.curs_set(0)
        screen.keypad(True)
        screen.timeout(1000)
        tab, selected, search = 4, 0, ''
        rows, error, refreshed = [], '', 0
        tabs = ('黑名单', '白名单', '操作历史', '健康检查', '总览看板', '数据与维护')

        def put(y, text, highlight=False):
            height, width = screen.getmaxyx()
            if 0 <= y < height:
                try:
                    screen.addstr(y, 0, fit(text, max(0, width - 1)), curses.A_REVERSE if highlight else 0)
                except curses.error:
                    pass

        def prompt(title):
            screen.erase()
            put(0, title)
            put(2, '输入后按 Enter；Esc 取消')
            text = ''
            screen.timeout(-1)
            try:
                while True:
                    put(4, ' ' * max(1, screen.getmaxyx()[1] - 1))
                    put(4, '> ' + text)
                    screen.refresh()
                    key = screen.get_wch()
                    if key == '\x1b':
                        return None
                    if key in ('\n', '\r', curses.KEY_ENTER):
                        return text
                    if key in ('\b', '\x7f', curses.KEY_BACKSPACE):
                        text = text[:-1]
                    elif isinstance(key, str) and key.isprintable() and len(text) < 200:
                        text += key
            finally:
                screen.timeout(1000)

        def popup(lines):
            offset = 0
            screen.timeout(-1)
            try:
                while True:
                    screen.erase()
                    height = screen.getmaxyx()[0]
                    for index, line in enumerate(lines[offset:offset + max(1, height - 2)]):
                        put(index, line)
                    put(height - 1, '↑↓ 滚动  其他键返回')
                    screen.refresh()
                    key = screen.getch()
                    if key == curses.KEY_DOWN:
                        offset = min(max(0, len(lines) - 1), offset + 1)
                    elif key == curses.KEY_UP:
                        offset = max(0, offset - 1)
                    elif key != curses.KEY_RESIZE:
                        return
            finally:
                screen.timeout(1000)

        while True:
            now = time.monotonic()
            if now - refreshed > 2:
                try:
                    if tab == 0:
                        rows = store.listing(10000, search)
                    elif tab == 1:
                        rows = store.query('SELECT * FROM allowlist WHERE instr(ip,?)>0 ORDER BY added_at DESC', (search,))
                    elif tab == 2:
                        rows = store.query('SELECT * FROM admin_events WHERE instr(ip,?)>0 ORDER BY id DESC LIMIT 1000', (search,)) if store.has('admin_events') else []
                    elif tab == 3:
                        rows = health(config, store)
                    elif tab == 4:
                        from f2block_manage import overview
                        rows = [{'text': line} for line in overview(config, store)]
                    else:
                        rows = [{'text': line} for line in (
                            'E 导出：CSV / JSON，黑名单 / 白名单',
                            'I 导入：校验、去重、预览后确认，合并名单',
                            '黑名单导入跳过白名单和人工解封；不导入历史计数',
                            'X 卸载：保留数据库、配置、备份及现有防火墙封禁',
                            '卸载后如需放行，请提前在黑名单页解封')]

                    counts, state = store.counts(), store.state()
                    error = ''
                except (OSError, sqlite3.Error, ValueError) as exc:
                    rows, counts, state, error = [], {}, {}, str(exc)
                refreshed = now
            screen.erase()
            height, width = screen.getmaxyx()
            if height < 10 or width < 50:
                put(0, '终端太小，请调整到至少 50 列 × 10 行；Q 退出')
                screen.refresh()
                if screen.getch() in (ord('q'), ord('Q')):
                    return 0
                continue
            age = time.time() - float(state.get('heartbeat', '0'))
            alive = '后台在线' if -5 <= age < 90 else '后台心跳异常'
            put(0, f"f2block · {alive} · 永久封禁 · 黑名单 {counts.get('blocked', '—')} · 白名单 {counts.get('allowed', '—')}")
            put(1, '  '.join(f"{'[' if i == tab else ''}{i + 1} {name}{']' if i == tab else ''}" for i, name in enumerate(tabs)))
            put(2, f"搜索：{search or '全部'}    {error or state.get('last_error') or state.get('geo_error', '')}")
            put(3, ('IP                 国家   次数   最近封禁', 'IP                 加入时间',
                    'IP                 操作         时间 / 原因', '检查项 / 结果', '总览（↑↓翻阅）', '数据与维护')[tab])
            selected = max(0, min(selected, len(rows) - 1))
            page_size = height - 6
            start = selected // page_size * page_size
            for index, row in enumerate(rows[start:start + page_size], start):
                if tab == 0:
                    line = f"{row['ip']:<18} {row.get('country') or '—':<6} {row['ban_count']:<6} {row['last_ban_time']}"
                elif tab == 1:
                    line = f"{row['ip']:<18} {row['added_at']}"
                elif tab == 2:
                    line = f"{row['ip']:<18} {row['action']:<12} {row['action_time']}  {row.get('reason', '')}"
                elif tab >= 4:
                    line = row['text']
                else:
                    line = f"[{'正常' if row['ok'] else '异常'}] {row['name']}：{row['detail']}"
                put(4 + index - start, line, index == selected)
            put(height - 2, f'{selected + 1 if rows else 0}/{len(rows)}  ↑↓/PgUp/PgDn  ←→切页  /搜索  R刷新')
            put(height - 1, 'E导出  I导入  X卸载  Q退出' if tab == 5 else '1-6切页  Enter详情  U解封  A加白  D移白  Q退出')
            screen.refresh()
            key = screen.getch()
            if key in (ord('q'), ord('Q')):
                return 0
            if key == curses.KEY_UP:
                selected = max(0, selected - 1)
            elif key == curses.KEY_DOWN:
                selected = min(len(rows) - 1, selected + 1)
            elif key in (curses.KEY_NPAGE, curses.KEY_PPAGE):
                selected = max(0, min(len(rows) - 1, selected + (page_size if key == curses.KEY_NPAGE else -page_size)))
            elif key in (curses.KEY_LEFT, curses.KEY_RIGHT) or ord('1') <= key <= ord('6'):
                tab = (tab + (1 if key == curses.KEY_RIGHT else -1)) % len(tabs) if key in (curses.KEY_LEFT, curses.KEY_RIGHT) else key - ord('1')
                selected, refreshed = 0, 0
            elif key in (ord('r'), ord('R')):
                refreshed = 0
            elif key == ord('/') and tab < 3:
                answer = prompt('搜索 IP 或组织；留空清除搜索')
                if answer is not None:
                    search, selected, refreshed = answer, 0, 0
            elif tab == 5 and key in (ord('e'), ord('E'), ord('i'), ord('I'), ord('x'), ord('X')):
                from f2block_manage import export_lists, read_import, import_lists, uninstall_program
                try:
                    action = chr(key).lower()
                    if action == 'x':
                        if prompt('卸载程序，保留数据、配置、备份和现有封禁。输入 uninstall 确认') != 'uninstall':
                            continue
                        task = lambda: uninstall_program(True)
                    else:
                        kind = prompt('名单类型：输入 blocked（黑名单）或 allowed（白名单）')
                        if kind is None:
                            continue
                        if kind not in ('blocked', 'allowed'):
                            popup(['名单类型无效'])
                            continue
                        if action == 'e':
                            format = prompt('导出格式：csv 或 json（导出到启动面板时的工作目录）')
                            if format is None:
                                continue
                            task = lambda: export_lists(store, format, kind)
                        else:
                            path = prompt('输入 CSV / JSON 文件完整路径')
                            if path is None:
                                continue
                            addresses, duplicates = read_import(path)
                            if prompt(f'有效 IP {len(addresses)}，重复 {duplicates}；合并到 {kind}。输入 yes 确认') != 'yes':
                                continue
                            task = lambda: import_lists(config, store, addresses, kind)
                    curses.def_prog_mode()
                    curses.endwin()
                    try:
                        result = task()
                        if action == 'x' and result == 0:
                            return 0
                        if result:
                            print(f'维护操作失败（返回码 {result}）。请查看上方输出或运行 doctor。')
                        input('\n按 Enter 返回面板…')
                    except (OSError, ValueError, sqlite3.Error) as exc:
                        print(clean(exc))
                        input('\n按 Enter 返回面板…')
                    finally:
                        curses.reset_prog_mode()
                        screen.clear()
                        refreshed = 0
                except (OSError, ValueError, sqlite3.Error) as exc:
                    popup([str(exc)])
                except EOFError:
                    return 0
            elif key in (10, 13, curses.KEY_ENTER) and rows and tab < 4:
                row = rows[selected]
                try:
                    popup(describe(store.details(row['ip'])) if tab != 3 else [row['name'], row['detail']])
                except (OSError, sqlite3.Error) as exc:
                    popup([str(exc)])
            elif key in (ord('u'), ord('U'), ord('a'), ord('A'), ord('d'), ord('D')) and rows and tab < 3:
                ip = rows[selected]['ip']
                action = {'u': 'unban', 'a': 'allow', 'd': 'allowdel'}[chr(key).lower()]
                message = {'unban': '解除当前永久封禁，未来新 Ban 可再次封禁',
                           'allow': '加入永久白名单并解除现有封禁',
                           'allowdel': '移除白名单，未来新 Ban 可再次封禁'}[action]
                answer = prompt(f'{ip}：{message}。输入 yes 确认')
                if answer != 'yes':
                    continue
                reason = prompt('输入操作原因（可留空）')
                if reason is None:
                    continue
                curses.def_prog_mode()
                curses.endwin()
                try:
                    result = operate(config, store, action, ip, reason)
                    input('\n操作完成。按 Enter 返回面板…' if result == 0 else '\n操作未完全成功，请查看上述结果。按 Enter 返回…')
                except (OSError, sqlite3.Error, EOFError) as exc:
                    print(clean(exc))
                finally:
                    curses.reset_prog_mode()
                    screen.clear()
                    refreshed = 0

    try:
        return curses.wrapper(session)
    except curses.error as exc:
        print('终端初始化失败：' + clean(exc) + '；可改用 f2block list。')
        return 1
    except (ValueError, TypeError) as exc:
        print('终端状态读取失败：' + clean(exc) + '；请运行 f2block doctor 检查后台状态。')
        return 1
