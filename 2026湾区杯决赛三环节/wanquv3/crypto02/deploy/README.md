# deploy · round3_1700 / crypto02

本题是**纯离线静态题**（无容器、无网络交互），因此 `deploy/` 只放**出题侧源码**，不含 `Dockerfile` / `docker-compose.yml`。

## 文件

| 文件 | 性质 | 说明 |
|------|------|------|
| `src/task.py` | **原始件**（逐字节，md5 `7d3d7b38b57752b69fcf3905ebc2a9fb`） | 平台附件 `attachments/crypto02.zip` 内唯一真实文件，就是出题脚本本身 |
| `src/secret.py` | **重建件** | 附件未下发；只含 `flag`（比赛真实 flag，`bytes` 类型）。文件头有来源标注 |

## 复现原始这道题

```bash
cd deploy/src
python task.py
# 打印 gift / key1 / cipher  ← 每次运行都是**新实例**
```

⚠️ 与 round3 crypto01 不同，本题**天然"重跑即出新题"**：`key0 = os.urandom(16).hex()` 且
`random.shuffle(tables)` 未播种，所以每次执行 `task.py` 都会得到全新的 `key0` / `key1` / `gift` / `cipher`，
唯一不变的是 `secret.py` 里的 flag。

## 用求解器闭环验证新实例

```bash
cd deploy/src
python task.py > /tmp/inst.txt 2>&1
python ../../solve/solve.py --from-file /tmp/inst.txt
# [+] key0 = <新 key0>   [+] FLAG = flag{886769b5-2301-4c37-bb73-4480b4eab682}
```

实测（2026-09-21）：新实例 `key1 = c11e54fa64b8929f3fdab1aacbb6fefe`、
`key0 = e774230f13a9b5b0d0cfa7ffeaa10404`，求解器正确恢复出 flag。

> 注意：`--from-file` 兼容 PowerShell `>` 重定向产出的 UTF-16LE+BOM 文本
> （见 `solve/solve.py` 的 `read_text_any()`）。

## 换 flag 造一道"新题"

改 `secret.py` 里的 `flag`（**必须是 bytes**）即可；`task.py` 会自然生成新的 `gift`/`key1`/`cipher`。

## 注意

- `flag` 必须是 `bytes`：`task.py` 的 `pad(msg)` 做的是 `msg + bytes(...)`，传 `str` 会
  `TypeError: can't concat str to bytes`。
