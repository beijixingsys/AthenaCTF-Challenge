#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
round3_1700 / re01  ——  附件 main (Rust 静态 ELF64, stripped, 375192 B)
qid = cRvMHaJuYM9lKdqI   score = 500   category = reverse   题面：Unlock the secrets

一句话：stdin 读 48 字节 → 每 8 字节一块（共 6 块）送进**内嵌字节码虚拟机**做 32 轮
        ARX（Speck/Threefish 风格）变换 → 把 16 个 dword 寄存器堆转成小端字节流（64 B）
        → 只取前 0x30 = 48 字节与硬编码常量 memcmp → 相等打印 "yes"。

本脚本 **不依赖原二进制** 即可出 flag（内嵌 VM 程序 + 目标常量），
若提供 --bin 则会从原 ELF 现场抽出 VM 程序与目标常量做**交叉校验**。

═══════════════════════════════════════════════════════════════════════════════
一、二进制事实（本次实测确认）
═══════════════════════════════════════════════════════════════════════════════
  ELF：ELF64 x86-64, Type DYN (PIE), stripped（无 .symtab）, 静态（NEEDED: libgcc_s.so.1, libc.so.6）
  .interp = /lib64/ld-linux-x86-64.so.2
  _start = 0x7950            main 区域 ≈ 0x9db0（Rust std main 包装）
  .text = 0x5050..0x480c2    .rodata = 0x49000..

  关键地址（全部为**文件偏移 == 虚拟地址**，本 ELF 的 PT_LOAD 段满足 off==vaddr）：
    0x4ae07   内嵌字节码 VM 程序，长度 0x1101 = 4353 字节
    0x4bf08   硬编码目标常量，长度 0x30 = 48 字节
              = 2c644803b15515d2e1d83f2a374213e6bcc74ac6f5f2bf6482717b20f94894fe645052a09a11c83e6b7dc6d51b91e4ee
    0x4bf38   "no\n"
    0x4bf3b   "yes\n"
    0x492b0   opcode 跳表（14 项 int32 相对偏移，基址 = 表项自身地址）
    0x8c60    calloc(0x40, 1)  → 16 个 dword 寄存器堆
    0x8c50/0x8c56  edi=0x40, esi=1（即 calloc(0x40,1)）
    0x8c8c    从输入缓冲区把**前 8 字节小端拼 2 个 dword** 填入 r[0], r[1]
    0x8cee    movaps xmm0,[0x49010] ; movups [r13+8],xmm0
    0x8cfa    movabs rax,0xdf0adbacefaedfe ; mov [r13+0x18],rax
    0x8d1d    VM 分派器：movzx eax,[rdi+r12]; dec eax; cmp eax,0xd; ja 结束;
              movsxd rax,[rbp+rax*4]; add rax,rbp; jmp rax
    0x8d10    cmp rdi,0x1101（程序长度边界）
    0x92d0..  VM 结束后把 r[i] & 0xffffffff 依次 **小端** 压入输出 Vec（4 字节/寄存器）
    0x941c    cmp r12,0x30（收集到的字节数 == 48?）
    0x9443    rsi = 0x4bf08（目标常量）
    0x944a    edx = 0x30
    0x9452    call [rip+0x52af0] = [0x5bf48]（GOT 里是 **bcmp**）
    0x950c    → 打印 "yes\n"（0x4bf3b），否则 "no\n"（0x4bf38）

  寄存器初值（.rodata 0x49010 的 16 字节 + 紧随的 8 字节 movabs）：
    0x49010: 00 00 00 00 | aa aa aa aa | 13 37 c0 de | de ad be ef
             r2 = 0x00000000            r5 = 0xefbeadde
             r3 = 0xaaaaaaaa            (由 mov ups 一次写入 4 个 dword)
               ↑ movups [r13+8],xmm0  → r2=00000000, r3=aaaaaaaa, r4=1337c0de, r5=deadbeef
    movabs 0xdf0adbacefaedfe → [r13+0x18] → r6 = 0xcefaedfe, r7 = 0x0df0adba

    ★★★ 唯一的坑（本 Script 的核心正确性条件）★★★
    寄存器堆是 **dword 数组**，而 `13 37 c0 de` 这 4 个字节按 **小端** 解释才是
        r4 = 0xdec03713
    而不是"看起来更顺眼"的 0x1337c0de。同理：
        r5 = 0xefbeadde（字节 de ad be ef）、r6 = 0xcefaedfe（fe ed fa ce）、
        r7 = 0x0df0adba（ba ad f0 0d）、r3 = 0xaaaaaaaa
    这 4 个常量显然是出题人照着 `1337c0de deadbeef fe ed fa ce ba ad f0 0d` 的**字节串**
    敲进去的；把它们当成"大端 dword 常量"读会得到一组**完全不同**的值，
    反演出的 block 全是乱码 —— 而且**不会报错**（XOR/加法都是双射），是纯粹的静默失败。

═══════════════════════════════════════════════════════════════════════════════
二、字节码 ISA（从 0x8d1d 跳表 + 14 个 handler 读出）
═══════════════════════════════════════════════════════════════════════════════
  每条指令第 1 字节 = opcode（1..14，`dec eax; cmp eax,0xd; ja` 越界即结束 VM）。
  reg 字段是**字节**（`movzx`, `cmp rax,0x10` 越界检查 → 16 个寄存器）。

  op 1  movimm  r[a] = imm32                    (len 6: op,a,imm32)
  op 2  mov     r[a] = r[b]                     (len 3)
  op 3  addrr   r[a] += r[b]                    (len 3)
  op 4  addimm  r[a] += imm32                   (len 6)
  op 5  subimm  r[a] -= imm32                   (len 6)
  op 6  addrr   r[a] += r[b]                    (len 3)  ← handler 在 0x912a，与 op3 等价
  op 7  xorrr   r[a] ^= r[b]                    (len 3)
  op 8  xorimm  r[a] ^= imm32                   (len 6)
  op 9  shlimm  r[a] = r[b] << r[c]             (len 4: op,a,b,c 均为 reg 索引)
  op 10 shrimm  r[a] = r[b] >> r[c]   (逻辑右移) (len 4)
  op 11 nop                                      (len 1)
  op 12 shlrr   r[a] = r[b] << (r[c] & 31)      (len 4)
  op 13 shrre   r[a] = r[b] >> (r[c] & 31) 逻辑 (len 4)
  op 14 andimm  r[a] = r[b] & imm32             (len 7: op,a,b,imm32)

  全文统计（1121 条指令）：movimm 0 / mov 128 / addrr 320 / addimm 96 / subimm 0 /
  xorrr 192 / xorimm 64 / shlimm+shrimm 0 / nop 65 / shlrr 64 / shrre 64 / andimm 128
  → 全部操作都是 **双向可逆**（ADD/SUB/XOR 自逆或互逆；SHL 由 `&31` 掩码保证双射；
    AND 只用作 `& 31` 取移位量，不破坏待反演数据）。

═══════════════════════════════════════════════════════════════════════════════
三、VM 程序结构 = 32 轮 Feistel-ARX（Speck / Threefish 风格）
═══════════════════════════════════════════════════════════════════════════════
  程序由 64 个"块"组成，顺序是 **ABAB…AB**（32 个 A + 32 个 B，实测 SEQ 打印为
  "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"）。

  A 块（偏移 0 起，功能：更新 r2 轮常量 + 更新 r0）：
      addimm r2, +0xaaaaaaaa          ; r2 += R2STEP   ← 每轮递推一次的"轮密钥"
      andimm r11, r5, 31              ; sa = r5 & 31
      shlrr  r8,  r1, r11             ; t  = r1 << sa
      addrr  r8,  r4                  ; t += r4          (ca)
      mov    r9,  r1
      addrr  r9,  r2                  ; r9 = r1 + r2
      andimm r12, r4, 31              ; sc = r4 & 31
      shrre  r10, r1, r12             ; t2 = r1 >> sc
      addrr  r10, r5                  ; t2 += r5         (cc)
      xorrr  r8,  r9                  ; t ^= (r1 + r2)
      xorrr  r8,  r10                 ; t ^= ((r1 >> sc) + cc)
      mov    r14, r4
      addrr  r14, r5                  ; r14 = ca + cc
      xorrr  r8,  r14                 ; t ^= (ca + cc)
      addrr  r0,  r8                  ; r0 += t            ← 唯一修改 r0 的指令

  B 块（功能：更新 r1，用**已经更新过的** r0）：
      andimm r11, r7, 31              ; sa = r7 & 31
      shlrr  r8,  r0, r11             ; t  = r0 << sa
      addrr  r8,  r6                  ; t += r6          (ca)
      mov    r9,  r0
      addrr  r9,  r2                  ; r9 = r0 + r2
      andimm r12, r6, 31              ; sc = r6 & 31
      shrre  r10, r0, r12             ; t2 = r0 >> sc
      addrr  r10, r7                  ; t2 += r7         (cc)
      xorrr  r8,  r9
      xorrr  r8,  r10
      mov    r14, r6
      addrr  r14, r7                  ; ca + cc
      xorrr  r8,  r14
      addrr  r1,  r8                  ; r1 += t            ← 唯一修改 r1 的指令

  即混洗函数（M32 = 2^32）：
      mix(x, r2, ca, sa, cc, sc)
          = ((x << sa) + ca) ^ (x + r2) ^ ((x >> sc) + cc) ^ (ca + cc)      (mod 2^32)
    A 轮参数 (x=r1)：sa = r5&31 = 0x1e = 30, ca = r4 = 0xdec03713,
                     sc = r4&31 = 0x13  = 19, cc = r5 = 0xefbeadde
    B 轮参数 (x=r0)：sa = r7&31 = 0x1a = 26, ca = r6 = 0xcefaedfe,
                     sc = r6&31 = 0x1e = 30, cc = r7 = 0x0df0adba
    ⇒ 设计上"刻意不对称"：A 与 B 用不同的 (sa, sc) 与不同的加常量，避免结构自相似。

  轮密钥：r2 初值 0，**只在每个 A 块开头 += 0xaaaaaaaa**（32 次）→ 轮常量序列
      r2_k = (k * 0xaaaaaaaa) mod 2^32 ,  k = 1..32
  这个序列完全由程序本身决定、与输入无关 ⇒ 反演时按同样规则正向预计算即可。

═══════════════════════════════════════════════════════════════════════════════
四、反演（本题的"最终一击"）
═══════════════════════════════════════════════════════════════════════════════
  因为每个块对它改写的那一半做的是 `rX += mix(other, r2, …)`：
    * 正向：第 i 块若为 A → r0 += mix(r1, r2_i, A-params)  （r1 尚未变）
            第 i 块若为 B → r1 += mix(r0, r2_i, B-params)  （r0 已是本轮新值）
    * 反向：从 i = 63 递减到 0，**块类型与当时的 r2_i 一一对应**（r2 序列与块序无关，
            只与"A 块出现次数"有关）→
              A: r0 -= mix(r1, r2_i, A-params)
              B: r1 -= mix(r0, r2_i, B-params)
  故 `invert(t0, t1)` 是 `forward(r0, r1)` 的精确逆，**无需 z3 / 无需求解器**
  （比赛中另有一条 z3 符号执行路线，但加法可逆性让这条更短）。

  6 个 8 字节块各自独立做同一套 32 轮 → 对目标常量按 8 字节切 6 段，逐段 invert
  → 拼回即为 48 字节明文，实测 = flag + 6 个 \x00（输入被 Rust 侧读取/补齐到 48 字节）。

用法
----
    python solve.py                                  # 内嵌 VM 程序 + 内嵌目标常量求解
    python solve.py --bin ../attachments/main        # 从原 ELF 现场抽 VM 程序/常量交叉校验
    python solve.py --dump-vm vmprog.bin             # 导出内部使用的 VM 程序（便于复现）
    python solve.py --dump-disasm vm.txt             # 导出翻译后的 1121 条伪汇编
"""
import argparse
import os
import struct
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROUND = "round3_1700"
NAME = "re01"
QID = "cRvMHaJuYM9lKdqI"
EXPECTED_FLAG = "flag{9bc396fd-75fb-484c-b193-f3ae596e6317}"

M32 = 0xFFFFFFFF

# ---- 关键地址（文件偏移 == 虚拟地址） ----
ADDR_VM_PROG = 0x4AE07
VM_PROG_LEN = 0x1101
ADDR_TARGET = 0x4BF08
TARGET_LEN = 0x30
ADDR_REGTABLE = 0x49010     # movaps xmm0,[rip+0x4031b] 的 16 字节
IMM_MOVABS = 0xDF0ADBACEFAEDFE   # movabs rax,0xdf0adbacefaedfe -> [r13+0x18]

# ---- 寄存器初值（★ 小端 dword 解释，唯一正确口径）----
R0, R1 = None, None                 # 由输入 8 字节小端填入
R2_INIT = 0x00000000
R3 = 0xAAAAAAAA
R4 = 0xDEC03713                     # .rodata 0x49010 的 "13 37 c0 de"
R5 = 0xEFBEADDE                     # .rodata 0x49010 的 "de ad be ef"
R6 = 0xCEFAEDFE                     # movabs 低 dword（fe ed fa ce）
R7 = 0x0DF0ADBA                     # movabs 高 dword（ba ad f0 0d）
R2STEP = 0xAAAAAAAA

# mix 参数（由 r4..r7 派生，与 A/B 块的寄存器选择一致）
SA_A, CA_A, SC_A, CC_A = R5 & 31, R4, R4 & 31, R5
SA_B, CA_B, SC_B, CC_B = R7 & 31, R6, R6 & 31, R7

EMBEDDED_TARGET = bytes.fromhex(
    "2c644803b15515d2e1d83f2a374213e6bcc74ac6f5f2bf6482717b20f94894fe"
    "645052a09a11c83e6b7dc6d51b91e4ee")

# 内嵌 VM 程序（0x1101 = 4353 字节，摘自 attachments/main @0x4ae07）
_PROG_HEX = (
    "0402aaaaaaaa0e0b051f0000000c08010b0608040209010609020e0c041f0000000d0a010c060a0507080907080a020e"
    "04060e0507080e060008080d00000000040d000000000b0e0b071f0000000c08000b0608060209000609020e0c061f00"
    "00000d0a000c060a0707080907080a020e06060e0707080e060108080d00000000040d000000000b0402aaaaaaaa0e0b"
    "051f0000000c08010b0608040209010609020e0c041f0000000d0a010c060a0507080907080a020e04060e0507080e06"
    "0008080d00000000040d000000000b0e0b071f0000000c08000b0608060209000609020e0c061f0000000d0a000c060a"
    "0707080907080a020e06060e0707080e060108080d00000000040d000000000b0402aaaaaaaa0e0b051f0000000c0801"
    "0b0608040209010609020e0c041f0000000d0a010c060a0507080907080a020e04060e0507080e060008080d00000000"
    "040d000000000b0e0b071f0000000c08000b0608060209000609020e0c061f0000000d0a000c060a0707080907080a02"
    "0e06060e0707080e060108080d00000000040d000000000b0402aaaaaaaa0e0b051f0000000c08010b06080402090106"
    "09020e0c041f0000000d0a010c060a0507080907080a020e04060e0507080e060008080d00000000040d000000000b0e"
    "0b071f0000000c08000b0608060209000609020e0c061f0000000d0a000c060a0707080907080a020e06060e0707080e"
    "060108080d00000000040d000000000b0402aaaaaaaa0e0b051f0000000c08010b0608040209010609020e0c041f0000"
    "000d0a010c060a0507080907080a020e04060e0507080e060008080d00000000040d000000000b0e0b071f0000000c08"
    "000b0608060209000609020e0c061f0000000d0a000c060a0707080907080a020e06060e0707080e060108080d000000"
    "00040d000000000b0402aaaaaaaa0e0b051f0000000c08010b0608040209010609020e0c041f0000000d0a010c060a05"
    "07080907080a020e04060e0507080e060008080d00000000040d000000000b0e0b071f0000000c08000b060806020900"
    "0609020e0c061f0000000d0a000c060a0707080907080a020e06060e0707080e060108080d00000000040d000000000b"
    "0402aaaaaaaa0e0b051f0000000c08010b0608040209010609020e0c041f0000000d0a010c060a0507080907080a020e"
    "04060e0507080e060008080d00000000040d000000000b0e0b071f0000000c08000b0608060209000609020e0c061f00"
    "00000d0a000c060a0707080907080a020e06060e0707080e060108080d00000000040d000000000b0402aaaaaaaa0e0b"
    "051f0000000c08010b0608040209010609020e0c041f0000000d0a010c060a0507080907080a020e04060e0507080e06"
    "0008080d00000000040d000000000b0e0b071f0000000c08000b0608060209000609020e0c061f0000000d0a000c060a"
    "0707080907080a020e06060e0707080e060108080d00000000040d000000000b0402aaaaaaaa0e0b051f0000000c0801"
    "0b0608040209010609020e0c041f0000000d0a010c060a0507080907080a020e04060e0507080e060008080d00000000"
    "040d000000000b0e0b071f0000000c08000b0608060209000609020e0c061f0000000d0a000c060a0707080907080a02"
    "0e06060e0707080e060108080d00000000040d000000000b0402aaaaaaaa0e0b051f0000000c08010b06080402090106"
    "09020e0c041f0000000d0a010c060a0507080907080a020e04060e0507080e060008080d00000000040d000000000b0e"
    "0b071f0000000c08000b0608060209000609020e0c061f0000000d0a000c060a0707080907080a020e06060e0707080e"
    "060108080d00000000040d000000000b0402aaaaaaaa0e0b051f0000000c08010b0608040209010609020e0c041f0000"
    "000d0a010c060a0507080907080a020e04060e0507080e060008080d00000000040d000000000b0e0b071f0000000c08"
    "000b0608060209000609020e0c061f0000000d0a000c060a0707080907080a020e06060e0707080e060108080d000000"
    "00040d000000000b0402aaaaaaaa0e0b051f0000000c08010b0608040209010609020e0c041f0000000d0a010c060a05"
    "07080907080a020e04060e0507080e060008080d00000000040d000000000b0e0b071f0000000c08000b060806020900"
    "0609020e0c061f0000000d0a000c060a0707080907080a020e06060e0707080e060108080d00000000040d000000000b"
    "0402aaaaaaaa0e0b051f0000000c08010b0608040209010609020e0c041f0000000d0a010c060a0507080907080a020e"
    "04060e0507080e060008080d00000000040d000000000b0e0b071f0000000c08000b0608060209000609020e0c061f00"
    "00000d0a000c060a0707080907080a020e06060e0707080e060108080d00000000040d000000000b0402aaaaaaaa0e0b"
    "051f0000000c08010b0608040209010609020e0c041f0000000d0a010c060a0507080907080a020e04060e0507080e06"
    "0008080d00000000040d000000000b0e0b071f0000000c08000b0608060209000609020e0c061f0000000d0a000c060a"
    "0707080907080a020e06060e0707080e060108080d00000000040d000000000b0402aaaaaaaa0e0b051f0000000c0801"
    "0b0608040209010609020e0c041f0000000d0a010c060a0507080907080a020e04060e0507080e060008080d00000000"
    "040d000000000b0e0b071f0000000c08000b0608060209000609020e0c061f0000000d0a000c060a0707080907080a02"
    "0e06060e0707080e060108080d00000000040d000000000b0402aaaaaaaa0e0b051f0000000c08010b06080402090106"
    "09020e0c041f0000000d0a010c060a0507080907080a020e04060e0507080e060008080d00000000040d000000000b0e"
    "0b071f0000000c08000b0608060209000609020e0c061f0000000d0a000c060a0707080907080a020e06060e0707080e"
    "060108080d00000000040d000000000b0402aaaaaaaa0e0b051f0000000c08010b0608040209010609020e0c041f0000"
    "000d0a010c060a0507080907080a020e04060e0507080e060008080d00000000040d000000000b0e0b071f0000000c08"
    "000b0608060209000609020e0c061f0000000d0a000c060a0707080907080a020e06060e0707080e060108080d000000"
    "00040d000000000b0402aaaaaaaa0e0b051f0000000c08010b0608040209010609020e0c041f0000000d0a010c060a05"
    "07080907080a020e04060e0507080e060008080d00000000040d000000000b0e0b071f0000000c08000b060806020900"
    "0609020e0c061f0000000d0a000c060a0707080907080a020e06060e0707080e060108080d00000000040d000000000b"
    "0402aaaaaaaa0e0b051f0000000c08010b0608040209010609020e0c041f0000000d0a010c060a0507080907080a020e"
    "04060e0507080e060008080d00000000040d000000000b0e0b071f0000000c08000b0608060209000609020e0c061f00"
    "00000d0a000c060a0707080907080a020e06060e0707080e060108080d00000000040d000000000b0402aaaaaaaa0e0b"
    "051f0000000c08010b0608040209010609020e0c041f0000000d0a010c060a0507080907080a020e04060e0507080e06"
    "0008080d00000000040d000000000b0e0b071f0000000c08000b0608060209000609020e0c061f0000000d0a000c060a"
    "0707080907080a020e06060e0707080e060108080d00000000040d000000000b0402aaaaaaaa0e0b051f0000000c0801"
    "0b0608040209010609020e0c041f0000000d0a010c060a0507080907080a020e04060e0507080e060008080d00000000"
    "040d000000000b0e0b071f0000000c08000b0608060209000609020e0c061f0000000d0a000c060a0707080907080a02"
    "0e06060e0707080e060108080d00000000040d000000000b0402aaaaaaaa0e0b051f0000000c08010b06080402090106"
    "09020e0c041f0000000d0a010c060a0507080907080a020e04060e0507080e060008080d00000000040d000000000b0e"
    "0b071f0000000c08000b0608060209000609020e0c061f0000000d0a000c060a0707080907080a020e06060e0707080e"
    "060108080d00000000040d000000000b0402aaaaaaaa0e0b051f0000000c08010b0608040209010609020e0c041f0000"
    "000d0a010c060a0507080907080a020e04060e0507080e060008080d00000000040d000000000b0e0b071f0000000c08"
    "000b0608060209000609020e0c061f0000000d0a000c060a0707080907080a020e06060e0707080e060108080d000000"
    "00040d000000000b0402aaaaaaaa0e0b051f0000000c08010b0608040209010609020e0c041f0000000d0a010c060a05"
    "07080907080a020e04060e0507080e060008080d00000000040d000000000b0e0b071f0000000c08000b060806020900"
    "0609020e0c061f0000000d0a000c060a0707080907080a020e06060e0707080e060108080d00000000040d000000000b"
    "0402aaaaaaaa0e0b051f0000000c08010b0608040209010609020e0c041f0000000d0a010c060a0507080907080a020e"
    "04060e0507080e060008080d00000000040d000000000b0e0b071f0000000c08000b0608060209000609020e0c061f00"
    "00000d0a000c060a0707080907080a020e06060e0707080e060108080d00000000040d000000000b0402aaaaaaaa0e0b"
    "051f0000000c08010b0608040209010609020e0c041f0000000d0a010c060a0507080907080a020e04060e0507080e06"
    "0008080d00000000040d000000000b0e0b071f0000000c08000b0608060209000609020e0c061f0000000d0a000c060a"
    "0707080907080a020e06060e0707080e060108080d00000000040d000000000b0402aaaaaaaa0e0b051f0000000c0801"
    "0b0608040209010609020e0c041f0000000d0a010c060a0507080907080a020e04060e0507080e060008080d00000000"
    "040d000000000b0e0b071f0000000c08000b0608060209000609020e0c061f0000000d0a000c060a0707080907080a02"
    "0e06060e0707080e060108080d00000000040d000000000b0402aaaaaaaa0e0b051f0000000c08010b06080402090106"
    "09020e0c041f0000000d0a010c060a0507080907080a020e04060e0507080e060008080d00000000040d000000000b0e"
    "0b071f0000000c08000b0608060209000609020e0c061f0000000d0a000c060a0707080907080a020e06060e0707080e"
    "060108080d00000000040d000000000b0402aaaaaaaa0e0b051f0000000c08010b0608040209010609020e0c041f0000"
    "000d0a010c060a0507080907080a020e04060e0507080e060008080d00000000040d000000000b0e0b071f0000000c08"
    "000b0608060209000609020e0c061f0000000d0a000c060a0707080907080a020e06060e0707080e060108080d000000"
    "00040d000000000b0402aaaaaaaa0e0b051f0000000c08010b0608040209010609020e0c041f0000000d0a010c060a05"
    "07080907080a020e04060e0507080e060008080d00000000040d000000000b0e0b071f0000000c08000b060806020900"
    "0609020e0c061f0000000d0a000c060a0707080907080a020e06060e0707080e060108080d00000000040d000000000b"
    "0402aaaaaaaa0e0b051f0000000c08010b0608040209010609020e0c041f0000000d0a010c060a0507080907080a020e"
    "04060e0507080e060008080d00000000040d000000000b0e0b071f0000000c08000b0608060209000609020e0c061f00"
    "00000d0a000c060a0707080907080a020e06060e0707080e060108080d00000000040d000000000b0402aaaaaaaa0e0b"
    "051f0000000c08010b0608040209010609020e0c041f0000000d0a010c060a0507080907080a020e04060e0507080e06"
    "0008080d00000000040d000000000b0e0b071f0000000c08000b0608060209000609020e0c061f0000000d0a000c060a"
    "0707080907080a020e06060e0707080e060108080d00000000040d000000000b0b"
)
_PROG_HEX = "".join(_PROG_HEX.split())


# ═══════════════════════════════════════════════════════════════════════
# 1) 从原 ELF 抽取 VM 程序 / 目标常量（交叉校验用）
# ═══════════════════════════════════════════════════════════════════════
def extract_from_binary(path):
    d = open(path, "rb").read()
    assert d[:4] == b"\x7fELF", "不是 ELF 文件: %s" % path
    prog = d[ADDR_VM_PROG:ADDR_VM_PROG + VM_PROG_LEN]
    tgt = d[ADDR_TARGET:ADDR_TARGET + TARGET_LEN]
    assert len(prog) == VM_PROG_LEN, "VM 程序长度不符"
    assert len(tgt) == TARGET_LEN, "目标常量长度不符"
    reg16 = d[ADDR_REGTABLE:ADDR_REGTABLE + 16]
    return prog, tgt, reg16


# ═══════════════════════════════════════════════════════════════════════
# 2) 字节码解码器（ISA 见文件头 §二）
# ═══════════════════════════════════════════════════════════════════════
def make_decoder(prog):
    def imm32(pc):
        return (prog[pc] | prog[pc + 1] << 8 | prog[pc + 2] << 16 | prog[pc + 3] << 24) & M32

    def decode(pc):
        """返回 (op, a, b, c, 指令长度)"""
        op = prog[pc]
        if op == 1:
            return ("movimm", prog[pc + 1], imm32(pc + 2), 0, 6)
        if op == 2:
            return ("mov", prog[pc + 1], prog[pc + 2], 0, 3)
        if op in (3, 6):                       # op3/op6 handler 均为 r[a] += r[b]
            return ("addrr", prog[pc + 1], prog[pc + 2], 0, 3)
        if op == 4:
            return ("addimm", prog[pc + 1], imm32(pc + 2), 0, 6)
        if op == 5:
            return ("subimm", prog[pc + 1], imm32(pc + 2), 0, 6)
        if op == 7:
            return ("xorrr", prog[pc + 1], prog[pc + 2], 0, 3)
        if op == 8:
            return ("xorimm", prog[pc + 1], imm32(pc + 2), 0, 6)
        if op == 9:
            return ("shlimm", prog[pc + 1], prog[pc + 2], prog[pc + 3], 4)
        if op == 10:
            return ("shrimm", prog[pc + 1], prog[pc + 2], prog[pc + 3], 4)
        if op == 11:
            return ("nop", 0, 0, 0, 1)
        if op == 12:
            return ("shlrr", prog[pc + 1], prog[pc + 2], prog[pc + 3], 4)
        if op == 13:
            return ("shrre", prog[pc + 1], prog[pc + 2], prog[pc + 3], 4)
        if op == 14:
            return ("andimm", prog[pc + 1], prog[pc + 2], imm32(pc + 3), 7)
        raise ValueError("未知 opcode %d @ %#x" % (op, pc))

    return decode


def disassemble(prog):
    decode = make_decoder(prog)
    pc, out = 0, []
    while pc < len(prog):
        op, a, b, c, ln = decode(pc)
        if op in ("movimm", "addimm", "subimm", "xorimm"):
            out.append("%04x: %-7s r%-2d, %#010x" % (pc, op, a, b))
        elif op == "andimm":
            out.append("%04x: %-7s r%-2d, r%-2d, %#010x" % (pc, op, a, b, c))
        elif op in ("shlrr", "shrre", "shlimm", "shrimm"):
            out.append("%04x: %-7s r%-2d, r%-2d, r%-2d" % (pc, op, a, b, c))
        elif op == "nop":
            out.append("%04x: nop" % pc)
        else:
            out.append("%04x: %-7s r%-2d, r%-2d" % (pc, op, a, b))
        pc += ln
    return out


# ═══════════════════════════════════════════════════════════════════════
# 3) 块序列提取（A = r0 += mix(r1,…)，B = r1 += mix(r0,…)）
# ═══════════════════════════════════════════════════════════════════════
def extract_blocks(prog):
    decode = make_decoder(prog)
    seq, pc = [], 0
    while pc < len(prog):
        op, a, b, _c, ln = decode(pc)
        if op == "addrr" and a == 0 and b == 8:
            seq.append("A")
        elif op == "addrr" and a == 1 and b == 8:
            seq.append("B")
        pc += ln
    return seq


# ═══════════════════════════════════════════════════════════════════════
# 4) ARX 混洗 + 正/反演
# ═══════════════════════════════════════════════════════════════════════
def mix(x, r2, sa, ca, sc, cc):
    """程序 A/B 块共同的反汇编结构：
       ((x << sa) + ca) ^ (x + r2) ^ ((x >> sc) + cc) ^ (ca + cc)   (mod 2^32)"""
    t = (((x << sa) & M32) + ca) & M32
    t ^= (x + r2) & M32
    t ^= (((x & M32) >> sc) + cc) & M32
    t &= M32
    t ^= (ca + cc) & M32
    return t & M32


def r2_sequence(seq):
    """r2 只在每个 A 块开头 += 0xaaaaaaaa；返回与 seq 等长的 r2 值序列。"""
    r2, vals = R2_INIT, []
    for blk in seq:
        if blk == "A":
            r2 = (r2 + R2STEP) & M32
        vals.append(r2)
    return vals


def forward(r0, r1, seq, r2s):
    for blk, r2 in zip(seq, r2s):
        if blk == "A":
            r0 = (r0 + mix(r1, r2, SA_A, CA_A, SC_A, CC_A)) & M32
        else:
            r1 = (r1 + mix(r0, r2, SA_B, CA_B, SC_B, CC_B)) & M32
    return r0, r1


def invert(t0, t1, seq, r2s):
    """加法可逆 ⇒ 从最后一轮往前，对当时被改写的那一半做减法。"""
    r0, r1 = t0, t1
    for blk, r2 in zip(reversed(seq), reversed(r2s)):
        if blk == "B":
            r1 = (r1 - mix(r0, r2, SA_B, CA_B, SC_B, CC_B)) & M32
        else:
            r0 = (r0 - mix(r1, r2, SA_A, CA_A, SC_A, CC_A)) & M32
    return r0, r1


# ═══════════════════════════════════════════════════════════════════════
# 5) 主流程
# ═══════════════════════════════════════════════════════════════════════
def main() -> int:
    ap = argparse.ArgumentParser(description="round3_1700 re01 solver (内嵌 VM + ARX 反演)")
    ap.add_argument("--bin", default=None, help="原 ELF main 路径（交叉校验 VM 程序/目标常量）")
    ap.add_argument("--dump-vm", default=None, help="把内部使用的 VM 程序写出到该文件")
    ap.add_argument("--dump-disasm", default=None, help="把翻译后的伪汇编写出到该文件")
    a = ap.parse_args()

    prog = bytes.fromhex(_PROG_HEX)
    target = EMBEDDED_TARGET
    assert len(prog) == VM_PROG_LEN, "内嵌 VM 程序长度异常: %d" % len(prog)
    print("[*] VM 程序长度 = %#x (%d B)  md5 见下" % (len(prog), len(prog)))
    import hashlib
    print("[*] VM 程序 md5 = %s" % hashlib.md5(prog).hexdigest())
    print("[*] 目标常量(%d B) = %s" % (len(target), target.hex()))

    if a.bin and os.path.exists(a.bin):
        bp, bt, reg16 = extract_from_binary(a.bin)
        assert bp == prog, "二进制 @0x4ae07 抽出的 VM 程序与内嵌值不一致!"
        assert bt == target, "二进制 @0x4bf08 抽出的目标常量与内嵌值不一致!"
        print("[+] 交叉校验通过：@0x4ae07 VM 程序 (0x1101 B) 与 @0x4bf08 目标常量 (0x30 B) 均一致")
        # 顺带核对寄存器初值表
        vals = struct.unpack("<4I", reg16)
        print("[*] .rodata@0x49010 十六进制 = %s" % reg16.hex())
        print("[*]   -> 小端 dword 解释: r2=%#010x r3=%#010x r4=%#010x r5=%#010x" % vals)
        lo, hi = IMM_MOVABS & M32, (IMM_MOVABS >> 32) & M32
        print("[*]   -> movabs 0x%016x 拆分: r6=%#010x r7=%#010x" % (IMM_MOVABS, lo, hi))
        assert vals == (R2_INIT, R3, R4, R5), "寄存器初值与推导不符!"
        assert (lo, hi) == (R6, R7), "movabs 拆分与推导不符!"
        print("[+] 寄存器初值口径核对通过（★ 必须是**小端 dword**：r4=0xdec03713 而不是 0x1337c0de）")

    if a.dump_vm:
        open(a.dump_vm, "wb").write(prog)
        print("[+] 已写出 VM 程序 -> %s" % a.dump_vm)
    if a.dump_disasm:
        with open(a.dump_disasm, "w", encoding="utf-8") as f:
            f.write("\n".join(disassemble(prog)) + "\n")
        print("[+] 已写出伪汇编 -> %s" % a.dump_disasm)

    seq = extract_blocks(prog)
    r2s = r2_sequence(seq)
    print("[*] 块序列: %d 块  A=%d  B=%d" % (len(seq), seq.count("A"), seq.count("B")))
    print("[*] 序列模式: %s" % "".join(seq))
    print("[*] A 轮参数: sa=r5&31=%d  ca=r4=%#010x  sc=r4&31=%d  cc=r5=%#010x"
          % (SA_A, CA_A, SC_A, CC_A))
    print("[*] B 轮参数: sa=r7&31=%d  ca=r6=%#010x  sc=r6&31=%d  cc=r7=%#010x"
          % (SA_B, CA_B, SC_B, CC_B))

    # ---- 自检 1：正演一个已知值（取自比赛期 VM 具体执行轨迹 A*8 -> ab3c514d ceded535）----
    f = forward(0x41414141, 0x41414141, seq, r2s)
    print("[*] 自检 forward(A*8) = %08x %08x (期望 4d513cab 35d5dece) -> %s"
          % (f[0], f[1], "OK" if f == (0x4D513CAB, 0x35D5DECE) else "MISMATCH"))

    # ---- 自检 2：反演 round-trip ----
    rt = invert(*f, seq, r2s)
    print("[*] 自检 invert(forward(x)) = %08x %08x -> %s"
          % (rt[0], rt[1], "OK" if rt == (0x41414141, 0x41414141) else "MISMATCH"))
    assert rt == (0x41414141, 0x41414141), "反演 round-trip 失败"
    assert f == (0x4D513CAB, 0x35D5DECE), "正演自检失败"

    # ---- 反演 6 个 8 字节块 ----
    out = bytearray()
    for i in range(len(target) // 8):
        t0, t1 = struct.unpack_from("<II", target, i * 8)
        p0, p1 = invert(t0, t1, seq, r2s)
        blk = struct.pack("<II", p0, p1)
        out += blk
        print("[*] block %d: %s | %r" % (i, blk.hex(" "), blk))

    print("[*] 完整 48 字节 = %r" % bytes(out))
    flag = bytes(out).split(b"\x00")[0]
    print("[+] flag = %s" % flag.decode("latin-1"))

    # ---- 自检 3：把明文重新正演，必须逐字节等于目标常量 ----
    seen = b"".join(
        struct.pack("<II", *forward(*struct.unpack_from("<II", bytes(out), i * 8), seq, r2s))
        for i in range(len(target) // 8))
    ok = seen == target
    print("[*] 自检 重加密(forward) == 目标常量 -> %s" % ("OK" if ok else "MISMATCH"))

    good = flag.decode("latin-1") == EXPECTED_FLAG
    print("[%s] 与比赛期确认 flag %s" % ("+" if good else "!", "一致 -> PASS" if good else "不一致"))
    return 0 if (ok and good) else 1


if __name__ == "__main__":
    sys.exit(main())
