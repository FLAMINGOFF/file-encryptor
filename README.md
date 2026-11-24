# File Encryptor

**English** | [简体中文](README.zh-CN.md)

A small Python CLI that encrypts and decrypts files with a password, using
**AES-256-GCM** for encryption and **Argon2id** to turn the password into a key.

- Tampering is detected: flipping a single bit, truncating the file, appending data,
  or reordering chunks makes decryption fail instead of silently producing garbage.
- Files are processed in 64 KiB chunks, so memory use stays flat for files of any size.
- A failed decryption never leaves a half-written plaintext file behind.

Requires Python 3.9+ and `cryptography` 44 or newer.

## Usage

```bash
pip install -r requirements.txt

python3 file_encrypt.py encrypt report.pdf              # → report.pdf.fenc (asks for password twice)
python3 file_encrypt.py decrypt report.pdf.fenc         # → report.pdf
python3 file_encrypt.py decrypt report.pdf.fenc -o copy.pdf
python3 file_encrypt.py info report.pdf.fenc            # show KDF parameters, no password needed

python3 file_encrypt.py encrypt big.iso --memory 256 --iterations 4   # stronger KDF
python3 file_encrypt.py encrypt notes.txt --delete-original
FENC_PASSWORD='...' python3 file_encrypt.py decrypt notes.txt.fenc     # for scripts
python3 file_encrypt.py decrypt notes.txt.fenc --password-file pw.txt

python3 -m unittest -v                                  # offline tests
```

Example output (the CLI prints in Chinese):

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

Existing output files are never overwritten unless you pass `-f/--force`.
Exit code is `0` on success and `1` on any error.

## Why these algorithms

### Key derivation: Argon2id, not a plain hash

A password is not a key. It is short and guessable, so if the key were just
`SHA-256(password)` an attacker with the encrypted file could try billions of
guesses per second on a GPU.

Argon2id (winner of the Password Hashing Competition, standardised in RFC 9106) is
deliberately slow and **memory-hard**: every guess must fill 64 MiB of RAM and make
3 passes over it. That costs about 0.1 s on a laptop, which is unnoticeable for you,
but it makes GPU and ASIC cracking far more expensive, because those chips have lots
of cores but little fast memory per core. The "id" variant combines Argon2i
(resists side-channel attacks) and Argon2d (resists GPU trade-offs).

A fresh random 16-byte **salt** is stored in every file, so the same password gives
a different key each time and precomputed tables are useless. The parameters are
stored in the header too, so you can raise them later and old files still decrypt.

Compared with alternatives: PBKDF2 is only CPU-hard (cheap to parallelise on GPUs);
scrypt is memory-hard too but Argon2id is the current recommendation from RFC 9106
and OWASP.

### Encryption: AES-256-GCM (authenticated encryption)

AES-GCM is an **AEAD** cipher: it gives confidentiality *and* integrity in one step.
Each chunk carries a 16-byte authentication tag; if anything changes, the tag check
fails and the tool refuses to output data. Plain "encrypt only" modes such as CBC or
CTR give no integrity, so an attacker could flip bits in the ciphertext and you would
decrypt modified data without noticing (and CBC padding errors have enabled padding
oracle attacks).

The 48-byte header (salt, parameters, nonce prefix) is passed to GCM as **associated
data**, so it is authenticated even though it is not encrypted. Nobody can, for
example, lower the KDF parameters in the header without decryption failing.

AES is hardware-accelerated (AES-NI / ARMv8 crypto) on almost every modern CPU, so
this runs at several hundred MB/s.

### Why not ECB

ECB (Electronic Codebook) encrypts each 16-byte block independently with the same
key, so **identical plaintext blocks become identical ciphertext blocks**. Patterns
in the data survive encryption: the famous example is a bitmap of the Linux penguin
that is still clearly visible after ECB encryption. ECB also has no integrity at all:
blocks can be deleted, repeated or swapped without detection. It should never be used
for data.

GCM uses a unique nonce per chunk, so the same input never encrypts to the same output.
The test suite checks this: 64 identical 16-byte blocks produce 64 different
ciphertext blocks.

### Chunking and nonces (STREAM construction)

Encrypting a whole file in one GCM call would mean loading it into memory. Instead,
the file is split into 64 KiB chunks, each encrypted separately (the "STREAM"
construction from Hoang, Reyhanitabar, Rogaway and Vizár, also used by Google Tink
and age). The 12-byte nonce for chunk *i* is:

```
nonce_prefix (7 random bytes) || i (4-byte counter) || last_flag (1 byte)
```

- The counter means chunks cannot be **reordered** or **dropped** from the middle.
- The last-chunk flag means the file cannot be **truncated** at a chunk boundary or
  have chunks **appended**.
- The random prefix plus a fresh key per file (new salt every time) means a
  (key, nonce) pair is never reused. Nonce reuse is the one fatal mistake with GCM.

### File format

```
header (48 bytes, authenticated as AAD on every chunk)
  magic "FENC" (4) | version (1) | chunk size exponent (1)
  Argon2 iterations (4) | memory KiB (4) | lanes (1)
  salt (16) | nonce prefix (7) | reserved zeros (10)
chunks
  AES-256-GCM(chunk) || 16-byte tag      ... repeated
```

Overhead is 48 bytes plus 16 bytes per 64 KiB (about 0.02%).

When decrypting, the header's Argon2 parameters are capped (4 GiB memory, 100
iterations) so a malicious file cannot make your machine allocate huge amounts of RAM.

## Limitations

- **Your password is the security.** A weak password can still be guessed; Argon2
  only makes each guess slower. Use a long passphrase or a password manager. There
  is no recovery if you forget it.
- `--delete-original` does a normal delete. On SSDs and journaling or copy-on-write
  filesystems, the original data may still be recoverable from disk. For sensitive
  data, rely on full-disk encryption (FileVault, BitLocker, LUKS) as well.
- Only the file contents are protected. The file name, approximate size and
  timestamps are visible.
- Passwords passed via `FENC_PASSWORD` can be seen by other processes of the same
  user and may end up in shell history. Prefer the interactive prompt or
  `--password-file` with restrictive permissions.
- This is a learning / portfolio project and has not been audited. For real-world
  use, consider [age](https://age-encryption.org) or GnuPG.

## Tests

```bash
python3 -m unittest -v
```

18 offline tests cover round trips of different sizes (empty file, chunk-size edges,
multi-chunk), wrong passwords, bit flips in header and body, truncation, appending,
chunk swapping, hostile KDF parameters, no-overwrite behaviour, no leftover file
after a failed decrypt, and the CLI.
