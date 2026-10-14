# deploy · round3_1700 / crypto01

本题是**纯离线静态题**（无容器、无网络交互），因此 `deploy/` 只放**出题侧源码**，不含 `Dockerfile` / `docker-compose.yml`。

## 文件

| 文件 | 性质 | 说明 |
|------|------|------|
| `src/task.py` | **原始件**（逐字节，md5 `7e469a7fd03ca4f5bfd7c7fb33a9792b`） | 平台附件 `attachments/crypto01.zip` 内唯一真实文件，就是出题脚本本身 |
| `src/secret.py` | **重建件**（反推） | 附件未下发；由 p/q 反推出 g/alpha/beta，flag 由解密得到。文件头有完整来源标注 |
| `src/verify_instance.py` | 重建件 | 校验 `secret.py` 能逐位复现原始 n / c |
| `src/gen_secret.py` | 重建件 | 生成**新实例**（换一份 g/alpha/beta/flag），用于"重跑即出新题" |

## 复现原始这道题

```bash
cd deploy/src
python verify_instance.py     # 应打印 n/c 一致 = True（已实测）
python task.py                # 应打印与附件注释里逐位相同的 n / c（已实测）
```

## 生成一道**新的**同类题

```bash
cd deploy/src
python gen_secret.py --flag "flag{my-new-instance}"     # 覆盖 secret.py，实测 0.57 s
python task.py                                          # 打印新的 n / c
python ../../solve/solve.py --from-file <(python task.py)   # 或把 stdout 存文件后 --from-file
```

`gen_secret.py` 的**关键设计**：先取 575 bit 素数 `g`，再在 24 bit 空间里**分别**搜索 `alpha` / `beta`
使 `2gα+1`、`2gβ+1` 为素数。反过来（先随机 α/β 再找 g 让 p、q 同时素）是三重素数约束，
期望尝试 ≈ `ln(g)·ln(p)·ln(q)` ≈ 400³ ≈ 6.4×10⁷，实际不可用。

## 注意

- `secret.py` 里 `flag` **必须是 `bytes`**：原始 `task.py` 写的是 `m = bytes_to_long(flag)`，
  传 `str` 会 `TypeError: can't concat str to bytes`（实测踩到）。`gen_secret.py` 已按 `bytes` 写出。
