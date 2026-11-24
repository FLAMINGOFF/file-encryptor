#!/usr/bin/env python3
"""
文件加密工具 (File Encryptor)

用口令加密 / 解密任意文件：
  - 密钥派生：Argon2id（RFC 9106），把口令 + 16 字节随机盐“慢速地”变成 256 位密钥，
    让暴力猜口令变得昂贵（默认 3 轮、64 MiB 内存、4 路并行）；
  - 加密：AES-256-GCM（认证加密），同时保证机密性和完整性——密文被改动一个比特，
    解密就会失败，而不是悄悄输出错误数据；
  - 分块：文件按 64 KiB 分块加密（STREAM 结构），内存占用固定，大文件也能处理，
    并能发现分块被截断、删除、调换顺序。

依赖：cryptography >= 44（提供 AESGCM 和 Argon2id）。Python 3.9+。

文件格式（所有整数为大端序）：
  header (48 字节，整体作为每一块的附加认证数据 AAD)
    magic        4  b"FENC"
    version      1  1
    chunk_exp    1  分块大小 = 2**chunk_exp 字节
    iterations   4  Argon2 time_cost
    memory_kib   4  Argon2 memory_cost (KiB)
    lanes        1  Argon2 并行度
    salt        16  随机盐
    nonce_prefix 7  随机 nonce 前缀
    reserved    10  全 0
  之后是若干块：每块 = AES-GCM(明文块) + 16 字节认证标签
  第 i 块的 nonce = nonce_prefix(7) || i(4 字节) || last_flag(1 字节，最后一块为 1)
"""

import argparse
import getpass
import os
import secrets
import struct
import sys
import tempfile

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
except ImportError:  # pragma: no cover
    sys.exit("需要 cryptography >= 44：pip install -r requirements.txt")

MAGIC = b"FENC"
VERSION = 1
SUFFIX = ".fenc"
HEADER_FMT = ">4sBBIIB16s7s10s"
HEADER_LEN = struct.calcsize(HEADER_FMT)  # 48
TAG_LEN = 16
KEY_LEN = 32  # AES-256

DEFAULT_CHUNK_EXP = 16  # 64 KiB
# RFC 9106 第 4 节第二推荐配置（内存受限场景）：t=3, m=64 MiB, p=4
DEFAULT_ITERATIONS = 3
DEFAULT_MEMORY_KIB = 64 * 1024
DEFAULT_LANES = 4

# 解密时接受的参数上限，防止恶意文件头让本机分配超大内存 / 跑很久
MAX_MEMORY_KIB = 4 * 1024 * 1024  # 4 GiB
MAX_ITERATIONS = 100
MAX_CHUNK_EXP = 24  # 16 MiB
MIN_CHUNK_EXP = 10  # 1 KiB
MAX_CHUNKS = 2 ** 32  # 4 字节计数器


class FencError(Exception):
    """可预期的错误：口令错误、文件损坏、格式不对等。"""


# ---------------------------------------------------------------- 文件头

def build_header(salt, nonce_prefix, iterations, memory_kib, lanes, chunk_exp):
    return struct.pack(HEADER_FMT, MAGIC, VERSION, chunk_exp, iterations,
                       memory_kib, lanes, salt, nonce_prefix, bytes(10))


def parse_header(data):
    if len(data) < HEADER_LEN:
        raise FencError("文件太短，不是本工具加密的文件")
    (magic, version, chunk_exp, iterations, memory_kib, lanes, salt,
     nonce_prefix, reserved) = struct.unpack(HEADER_FMT, data[:HEADER_LEN])
    if magic != MAGIC:
        raise FencError("文件头标识不对，不是本工具加密的文件")
    if version != VERSION:
        raise FencError(f"不支持的格式版本 {version}")
    if reserved != bytes(10):
        raise FencError("文件头保留字段非 0，文件可能损坏")
    if not MIN_CHUNK_EXP <= chunk_exp <= MAX_CHUNK_EXP:
        raise FencError("文件头分块大小异常")
    if not (1 <= iterations <= MAX_ITERATIONS and 1 <= lanes <= 255
            and 8 * lanes <= memory_kib <= MAX_MEMORY_KIB):
        raise FencError("文件头 Argon2 参数超出允许范围，拒绝处理")
    return {
        "chunk_exp": chunk_exp, "iterations": iterations,
        "memory_kib": memory_kib, "lanes": lanes,
        "salt": salt, "nonce_prefix": nonce_prefix,
    }


def derive_key(password, salt, iterations, memory_kib, lanes):
    if isinstance(password, str):
        password = password.encode("utf-8")
    if not password:
        raise FencError("口令不能为空")
    kdf = Argon2id(salt=salt, length=KEY_LEN, iterations=iterations,
                   lanes=lanes, memory_cost=memory_kib)
    return kdf.derive(password)


def chunk_nonce(prefix, index, last):
    return prefix + struct.pack(">IB", index, 1 if last else 0)


# ---------------------------------------------------------------- 流式加解密

def _read_full(f, n):
    """读满 n 字节（或到文件尾）。"""
    buf = bytearray()
    while len(buf) < n:
        part = f.read(n - len(buf))
        if not part:
            break
        buf += part
    return bytes(buf)


def encrypt_stream(src, dst, password, iterations=DEFAULT_ITERATIONS,
                   memory_kib=DEFAULT_MEMORY_KIB, lanes=DEFAULT_LANES,
                   chunk_exp=DEFAULT_CHUNK_EXP):
    salt = secrets.token_bytes(16)
    nonce_prefix = secrets.token_bytes(7)
    header = build_header(salt, nonce_prefix, iterations, memory_kib, lanes, chunk_exp)
    aes = AESGCM(derive_key(password, salt, iterations, memory_kib, lanes))
    chunk_size = 1 << chunk_exp

    dst.write(header)
    index = 0
    current = _read_full(src, chunk_size)
    while True:
        # 预读下一块，才能知道当前块是不是最后一块（空文件也会产生一个空的最后块）
        nxt = _read_full(src, chunk_size) if len(current) == chunk_size else b""
        last = not nxt
        if index >= MAX_CHUNKS:
            raise FencError("文件过大")
        dst.write(aes.encrypt(chunk_nonce(nonce_prefix, index, last), current, header))
        if last:
            return
        current = nxt
        index += 1


def decrypt_stream(src, dst, password):
    header = _read_full(src, HEADER_LEN)
    p = parse_header(header)
    aes = AESGCM(derive_key(password, p["salt"], p["iterations"],
                            p["memory_kib"], p["lanes"]))
    block = (1 << p["chunk_exp"]) + TAG_LEN

    index = 0
    current = _read_full(src, block)
    while True:
        if len(current) < TAG_LEN:
            raise FencError("密文被截断或损坏")
        nxt = _read_full(src, block) if len(current) == block else b""
        last = not nxt
        try:
            plain = aes.decrypt(chunk_nonce(p["nonce_prefix"], index, last), current, header)
        except InvalidTag:
            if index == 0:
                raise FencError("解密失败：口令错误，或文件已被篡改") from None
            raise FencError(f"解密失败：第 {index + 1} 块认证失败，文件已被篡改或截断") from None
        dst.write(plain)
        if last:
            return
        current = nxt
        index += 1


# ---------------------------------------------------------------- 文件级操作

def _atomic_write(out_path, force, writer):
    """先写同目录临时文件，成功后再改名。解密失败时不会留下半截明文。"""
    if os.path.exists(out_path) and not force:
        raise FencError(f"输出文件已存在：{out_path}（用 --force 覆盖）")
    out_dir = os.path.dirname(os.path.abspath(out_path))
    fd, tmp = tempfile.mkstemp(dir=out_dir, prefix=".fenc-tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            writer(f)
        os.replace(tmp, out_path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def encrypt_file(in_path, out_path, password, force=False, **params):
    with open(in_path, "rb") as src:
        _atomic_write(out_path, force, lambda dst: encrypt_stream(src, dst, password, **params))


def decrypt_file(in_path, out_path, password, force=False):
    with open(in_path, "rb") as src:
        _atomic_write(out_path, force, lambda dst: decrypt_stream(src, dst, password))


def file_info(in_path):
    with open(in_path, "rb") as f:
        p = parse_header(_read_full(f, HEADER_LEN))
    p["size"] = os.path.getsize(in_path)
    return p


def default_output(in_path, mode):
    if mode == "encrypt":
        return in_path + SUFFIX
    if in_path.endswith(SUFFIX):
        return in_path[: -len(SUFFIX)]
    return in_path + ".dec"


# ---------------------------------------------------------------- 命令行

def read_password(args, confirm):
    if args.password_file:
        with open(args.password_file, "r", encoding="utf-8") as f:
            pw = f.readline().rstrip("\r\n")
    elif os.environ.get("FENC_PASSWORD"):
        pw = os.environ["FENC_PASSWORD"]
    else:
        pw = getpass.getpass("口令: ")
        if confirm and getpass.getpass("再输一次: ") != pw:
            raise FencError("两次输入的口令不一致")
    if not pw:
        raise FencError("口令不能为空")
    if confirm and len(pw) < 12:
        print("[提示] 口令少于 12 个字符，建议使用更长的口令或随机短语。", file=sys.stderr)
    return pw


def build_parser():
    ap = argparse.ArgumentParser(
        description="文件加密工具：AES-256-GCM + Argon2id 口令加密 / 解密文件")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("input", help="输入文件")
        p.add_argument("-o", "--output", help="输出文件（默认加/去 .fenc 后缀）")
        p.add_argument("-f", "--force", action="store_true", help="覆盖已存在的输出文件")
        p.add_argument("--password-file", help="从文件第一行读取口令（用于脚本）")

    enc = sub.add_parser("encrypt", help="加密文件")
    common(enc)
    enc.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS,
                     help=f"Argon2 迭代次数（默认 {DEFAULT_ITERATIONS}）")
    enc.add_argument("--memory", type=int, default=DEFAULT_MEMORY_KIB // 1024,
                     help=f"Argon2 内存 MiB（默认 {DEFAULT_MEMORY_KIB // 1024}）")
    enc.add_argument("--lanes", type=int, default=DEFAULT_LANES,
                     help=f"Argon2 并行度（默认 {DEFAULT_LANES}）")
    enc.add_argument("--delete-original", action="store_true",
                     help="加密成功后删除原文件（注意：普通删除不等于安全擦除）")

    dec = sub.add_parser("decrypt", help="解密文件")
    common(dec)

    info = sub.add_parser("info", help="查看加密文件的参数（不需要口令）")
    info.add_argument("input")
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "info":
            p = file_info(args.input)
            print(f"格式:     FENC v{VERSION}  AES-256-GCM，分块 {1 << p['chunk_exp']} 字节")
            print(f"KDF:      Argon2id  t={p['iterations']}  m={p['memory_kib'] // 1024} MiB"
                  f"  p={p['lanes']}")
            print(f"盐:       {p['salt'].hex()}")
            print(f"文件大小: {p['size']} 字节")
            return 0

        out = args.output or default_output(args.input, args.cmd)
        if os.path.abspath(out) == os.path.abspath(args.input):
            raise FencError("输出文件不能和输入文件相同")
        if args.cmd == "encrypt":
            memory_kib = args.memory * 1024
            if not (1 <= args.iterations <= MAX_ITERATIONS and 1 <= args.lanes <= 255
                    and 8 * args.lanes <= memory_kib <= MAX_MEMORY_KIB):
                raise FencError("Argon2 参数超出允许范围")
            pw = read_password(args, confirm=True)
            encrypt_file(args.input, out, pw, force=args.force,
                         iterations=args.iterations, memory_kib=memory_kib, lanes=args.lanes)
            print(f"✅ 已加密：{args.input} → {out}")
            if args.delete_original:
                os.remove(args.input)
                print(f"   已删除原文件 {args.input}")
        else:
            pw = read_password(args, confirm=False)
            decrypt_file(args.input, out, pw, force=args.force)
            print(f"✅ 已解密：{args.input} → {out}")
        return 0
    except FencError as e:
        print(f"❌ {e}", file=sys.stderr)
        return 1
    except (OSError, KeyboardInterrupt) as e:
        print(f"❌ {e or '已取消'}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
