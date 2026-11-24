"""离线单元测试：python3 -m unittest -v"""

import io
import os
import tempfile
import unittest

import file_encrypt as fe

# 测试用很小的 Argon2 参数和 1 KiB 分块，跑得快，也能覆盖多块场景
FAST = dict(iterations=1, memory_kib=64, lanes=1, chunk_exp=10)
PW = "correct horse battery staple"


def enc(data, pw=PW, **kw):
    out = io.BytesIO()
    fe.encrypt_stream(io.BytesIO(data), out, pw, **{**FAST, **kw})
    return out.getvalue()


def dec(blob, pw=PW):
    out = io.BytesIO()
    fe.decrypt_stream(io.BytesIO(blob), out, pw)
    return out.getvalue()


class RoundTrip(unittest.TestCase):
    def test_sizes(self):
        cs = 1 << FAST["chunk_exp"]
        for n in (0, 1, cs - 1, cs, cs + 1, 3 * cs, 3 * cs + 7):
            with self.subTest(n=n):
                data = os.urandom(n)
                blob = enc(data)
                chunks = max(1, -(-n // cs))  # 向上取整，空文件也有 1 块
                self.assertEqual(len(blob), fe.HEADER_LEN + n + chunks * fe.TAG_LEN)
                self.assertEqual(dec(blob), data)

    def test_unicode_password(self):
        self.assertEqual(dec(enc(b"hi", pw="密码🔑"), pw="密码🔑"), b"hi")

    def test_random_salt_and_nonce(self):
        a, b = enc(b"same"), enc(b"same")
        self.assertNotEqual(a, b)  # 每次加密的盐和 nonce 都不同
        self.assertNotEqual(a[:fe.HEADER_LEN], b[:fe.HEADER_LEN])

    def test_identical_blocks_not_visible(self):
        # ECB 会把相同明文块加密成相同密文块；GCM 不会
        data = b"A" * 16 * 64
        body = enc(data)[fe.HEADER_LEN:]
        blocks = {body[i:i + 16] for i in range(0, len(data), 16)}
        self.assertEqual(len(blocks), 64)


class Tampering(unittest.TestCase):
    def setUp(self):
        self.data = os.urandom(3 * 1024 + 100)  # 4 块
        self.blob = enc(self.data)

    def assertFails(self, blob, pw=PW):
        with self.assertRaises(fe.FencError):
            dec(blob, pw)

    def test_wrong_password(self):
        with self.assertRaisesRegex(fe.FencError, "口令错误"):
            dec(self.blob, "wrong password")

    def test_flip_every_region(self):
        for pos in (fe.HEADER_LEN, fe.HEADER_LEN + 1500, len(self.blob) - 1):
            with self.subTest(pos=pos):
                b = bytearray(self.blob)
                b[pos] ^= 1
                self.assertFails(bytes(b))

    def test_header_tamper(self):
        # 改文件头里的盐 / nonce 前缀：头部是 AAD，必然认证失败
        for pos in (20, 35):
            b = bytearray(self.blob)
            b[pos] ^= 1
            self.assertFails(bytes(b))

    def test_truncate_at_chunk_boundary(self):
        block = 1024 + fe.TAG_LEN
        self.assertFails(self.blob[:fe.HEADER_LEN + 2 * block])

    def test_truncate_mid(self):
        self.assertFails(self.blob[:-5])
        self.assertFails(self.blob[:fe.HEADER_LEN + 3])

    def test_append(self):
        self.assertFails(self.blob + b"x" * 50)

    def test_swap_chunks(self):
        block = 1024 + fe.TAG_LEN
        h, body = self.blob[:fe.HEADER_LEN], self.blob[fe.HEADER_LEN:]
        swapped = h + body[block:2 * block] + body[:block] + body[2 * block:]
        self.assertFails(swapped)

    def test_not_fenc(self):
        self.assertFails(b"hello")
        self.assertFails(b"XXXX" + self.blob[4:])

    def test_hostile_kdf_params_rejected(self):
        h = fe.build_header(bytes(16), bytes(7), 1, fe.MAX_MEMORY_KIB + 1, 1, 10)
        with self.assertRaisesRegex(fe.FencError, "Argon2"):
            dec(h + bytes(32))


class Files(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.src = os.path.join(self.d, "secret.txt")
        with open(self.src, "wb") as f:
            f.write(b"top secret\n" * 500)

    def tearDown(self):
        self.tmp.cleanup()

    def p(self, name):
        return os.path.join(self.d, name)

    def test_file_roundtrip_and_info(self):
        out = fe.default_output(self.src, "encrypt")
        self.assertTrue(out.endswith(".fenc"))
        fe.encrypt_file(self.src, out, PW, **FAST)
        info = fe.file_info(out)
        self.assertEqual(info["iterations"], 1)
        self.assertEqual(info["memory_kib"], 64)
        back = self.p("back.txt")
        fe.decrypt_file(out, back, PW)
        with open(self.src, "rb") as a, open(back, "rb") as b:
            self.assertEqual(a.read(), b.read())

    def test_no_overwrite_without_force(self):
        out = self.p("x.fenc")
        fe.encrypt_file(self.src, out, PW, **FAST)
        with self.assertRaisesRegex(fe.FencError, "已存在"):
            fe.encrypt_file(self.src, out, PW, **FAST)
        fe.encrypt_file(self.src, out, PW, force=True, **FAST)

    def test_failed_decrypt_leaves_nothing(self):
        out = self.p("x.fenc")
        fe.encrypt_file(self.src, out, PW, **FAST)
        with self.assertRaises(fe.FencError):
            fe.decrypt_file(out, self.p("plain.txt"), "nope")
        self.assertEqual(sorted(os.listdir(self.d)), ["secret.txt", "x.fenc"])

    def test_default_output_names(self):
        self.assertEqual(fe.default_output("a.pdf", "encrypt"), "a.pdf.fenc")
        self.assertEqual(fe.default_output("a.pdf.fenc", "decrypt"), "a.pdf")
        self.assertEqual(fe.default_output("a.bin", "decrypt"), "a.bin.dec")

    def test_cli(self):
        pwf = self.p("pw.txt")
        with open(pwf, "w") as f:
            f.write(PW + "\n")
        enc_path = self.p("s.fenc")
        rc = fe.main(["encrypt", self.src, "-o", enc_path, "--password-file", pwf,
                      "--iterations", "1", "--memory", "1", "--lanes", "1"])
        self.assertEqual(rc, 0)
        self.assertEqual(fe.main(["info", enc_path]), 0)
        rc = fe.main(["decrypt", enc_path, "-o", self.p("out.txt"), "--password-file", pwf])
        self.assertEqual(rc, 0)
        with open(pwf, "w") as f:
            f.write("wrong\n")
        rc = fe.main(["decrypt", enc_path, "-o", self.p("bad.txt"), "--password-file", pwf])
        self.assertEqual(rc, 1)
        self.assertFalse(os.path.exists(self.p("bad.txt")))


if __name__ == "__main__":
    unittest.main()
