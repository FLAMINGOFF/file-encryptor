# 文件加密工具 File Encryptor

[English](README.md) | **简体中文**

一个用口令加密 / 解密文件的 Python 命令行小工具：用 **Argon2id** 把口令变成密钥，
用 **AES-256-GCM** 加密。

- 能发现篡改：改动一个比特、截断文件、追加数据、调换分块顺序，解密都会直接失败，
  而不是悄悄输出错误内容。
- 按 64 KiB 分块处理，文件再大内存占用也是固定的。
- 解密失败时不会留下写了一半的明文文件。

需要 Python 3.9+ 和 `cryptography` 44 及以上版本。

## 用法

```bash
pip install -r requirements.txt

python3 file_encrypt.py encrypt report.pdf              # → report.pdf.fenc（输入两次口令）
python3 file_encrypt.py decrypt report.pdf.fenc         # → report.pdf
python3 file_encrypt.py decrypt report.pdf.fenc -o copy.pdf
python3 file_encrypt.py info report.pdf.fenc            # 查看 KDF 参数，不需要口令

python3 file_encrypt.py encrypt big.iso --memory 256 --iterations 4   # 更强的 KDF 参数
python3 file_encrypt.py encrypt notes.txt --delete-original
FENC_PASSWORD='...' python3 file_encrypt.py decrypt notes.txt.fenc     # 脚本中使用
python3 file_encrypt.py decrypt notes.txt.fenc --password-file pw.txt

python3 -m unittest -v                                  # 离线测试
```

输出示例：

```
$ python3 file_encrypt.py encrypt secret.txt
口令:
再输一次:
✅ 已加密：secret.txt → secret.txt.fenc

$ python3 file_encrypt.py decrypt secret.txt.fenc -o out.txt
口令:
❌ 解密失败：口令错误，或文件已被篡改

$ python3 file_encrypt.py info secret.txt.fenc
格式:     FENC v1  AES-256-GCM，分块 65536 字节
KDF:      Argon2id  t=3  m=64 MiB  p=4
盐:       33701ee8b5ec1c3bece396ed3bf6169d
文件大小: 76 字节
```

输出文件已存在时默认不覆盖，需要加 `-f/--force`。成功退出码为 `0`，任何错误为 `1`。

## 为什么选这些算法

### 密钥派生：Argon2id，而不是直接哈希

口令不是密钥：它短、可猜。如果密钥只是 `SHA-256(口令)`，拿到加密文件的攻击者
可以用 GPU 每秒尝试几十亿个口令。

Argon2id（密码哈希竞赛 PHC 冠军，RFC 9106 标准）故意设计得慢，而且**吃内存**：
每猜一次都要占用 64 MiB 内存并遍历 3 轮。在笔记本上大约 0.1 秒，你感觉不到，
但 GPU / ASIC 核心多、每核可用的高速内存少，破解成本会大幅上升。
“id” 变体结合了 Argon2i（抗侧信道）和 Argon2d（抗 GPU 时间-内存折中攻击）。

每个文件都存一个新的 16 字节随机**盐**，同一口令每次得到的密钥都不同，
预计算的彩虹表没用。参数也写在文件头里，以后调高参数，旧文件照样能解。

对比：PBKDF2 只消耗 CPU，在 GPU 上很容易并行；scrypt 也吃内存，但 RFC 9106 和
OWASP 目前推荐的是 Argon2id。

### 加密：AES-256-GCM（认证加密）

AES-GCM 是 **AEAD** 算法：一步同时提供机密性和完整性。每块带 16 字节认证标签，
内容有任何改动，标签校验就失败，工具拒绝输出。CBC、CTR 这种“只加密”模式没有完整性：
攻击者可以翻转密文比特，你解出被改过的数据也察觉不到（CBC 的填充错误还导致过
padding oracle 攻击）。

48 字节的文件头（盐、参数、nonce 前缀）作为**附加认证数据（AAD）**传给 GCM：
它不加密，但受认证保护。比如有人想把文件头里的 KDF 参数调低，解密就会失败。

几乎所有现代 CPU 都有 AES 硬件加速（AES-NI / ARMv8），速度可达每秒数百 MB。

### 为什么不用 ECB

ECB（电子密码本）模式用同一个密钥把每个 16 字节块独立加密，所以**相同的明文块
会变成相同的密文块**，数据里的规律在加密后依然可见。最有名的例子是 Linux 企鹅
图片，用 ECB 加密后轮廓依旧清清楚楚。ECB 也完全没有完整性：块可以被删除、重复、
调换而不被发现。它不应该用来加密任何数据。

GCM 每块使用唯一的 nonce，同样的输入永远不会得到同样的输出。测试里专门验证了这一点：
64 个相同的 16 字节明文块，加密后是 64 个互不相同的密文块。

### 分块与 nonce（STREAM 结构）

整个文件一次性交给 GCM 就得全部读进内存。所以这里把文件切成 64 KiB 的块，逐块加密
（Hoang、Reyhanitabar、Rogaway、Vizár 提出的 STREAM 结构，Google Tink 和 age
也采用类似做法）。第 *i* 块的 12 字节 nonce 为：

```
nonce 前缀（7 字节随机数）|| i（4 字节计数器）|| 末块标志（1 字节）
```

- 计数器：块不能被**调换顺序**，也不能从中间**删掉**。
- 末块标志：文件不能在块边界处被**截断**，也不能**追加**块。
- 随机前缀 + 每个文件都是新密钥（每次新盐）：(密钥, nonce) 组合绝不重复。
  nonce 重用是使用 GCM 时唯一致命的错误。

### 文件格式

```
文件头（48 字节，作为 AAD 参与每一块的认证）
  魔数 "FENC" (4) | 版本 (1) | 分块大小指数 (1)
  Argon2 迭代次数 (4) | 内存 KiB (4) | 并行度 (1)
  盐 (16) | nonce 前缀 (7) | 保留 0 (10)
分块
  AES-256-GCM(明文块) || 16 字节标签      ……重复
```

额外开销为 48 字节 + 每 64 KiB 16 字节（约 0.02%）。

解密时会限制文件头里的 Argon2 参数上限（内存 4 GiB、100 轮），防止恶意文件让你的
机器分配巨量内存。

## 局限

- **安全性取决于口令。** 弱口令照样能被猜出来，Argon2 只是让每次猜测更慢。请使用
  长口令短语或密码管理器。忘记口令无法恢复。
- `--delete-original` 只是普通删除。在 SSD、日志型或写时复制文件系统上，原始数据
  可能仍能从磁盘恢复。敏感数据请同时开启全盘加密（FileVault、BitLocker、LUKS）。
- 只保护文件内容。文件名、大致大小、时间戳都是可见的。
- 通过 `FENC_PASSWORD` 传入的口令可能被同用户的其他进程看到，也可能留在 shell 历史里。
  优先使用交互输入，或权限受限的 `--password-file`。
- 这是学习 / 作品集项目，未经过安全审计。实际使用请考虑
  [age](https://age-encryption.org) 或 GnuPG。

## 测试

```bash
python3 -m unittest -v
```

18 个离线测试，覆盖：不同大小的往返加解密（空文件、分块边界、多块）、错误口令、
文件头和正文的比特翻转、截断、追加、调换分块、恶意 KDF 参数、默认不覆盖、
解密失败后不留文件，以及命令行。
