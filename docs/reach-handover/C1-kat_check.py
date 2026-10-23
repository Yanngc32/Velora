"""Independent re-implementation of the sealed-record layout documented at the top of crates/dht/src/seal.rs.

Written from that description, with the Python `cryptography` package (OpenSSL) instead of `ring`, to check that
the Rust code and the description agree and that the bytes are what any other ChaCha20-Poly1305 / HKDF-SHA256
implementation produces. Not part of the repository.
"""
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = 1
PURPOSE_WRAP = 1
PURPOSE_CONTENT = 2
LABEL = b"velora-dht/seal/v1 wrap key"


def wrap_key(secret: bytes) -> bytes:
    # HKDF-SHA256, no salt (zeros of the hash length), the fixed label as info, 32 bytes out.
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=LABEL).derive(secret)


def aad(purpose: int, salt: bytes, seq: int, header: bytes) -> bytes:
    return bytes([purpose, VERSION]) + seq.to_bytes(8, "big", signed=True) + len(salt).to_bytes(8, "big") + salt + header


def nonce_at(base: bytes, index: int) -> bytes:
    n = bytearray(base)
    n[-1] ^= index
    return bytes(n)


def seal(plain: bytes, salt: bytes, seq: int, secrets: list, content_key: bytes, nonce: bytes) -> bytes:
    header = bytes([len(secrets)]) + nonce
    for i, secret in enumerate(secrets, start=1):
        header += ChaCha20Poly1305(wrap_key(secret)).encrypt(nonce_at(nonce, i), content_key, aad(PURPOSE_WRAP, salt, seq, b""))
    payload = ChaCha20Poly1305(content_key).encrypt(nonce_at(nonce, 0), plain, aad(PURPOSE_CONTENT, salt, seq, header))
    return bytes([VERSION]) + header + payload


def open_(blob: bytes, salt: bytes, seq: int, secret: bytes) -> bytes:
    assert blob[0] == VERSION
    count = blob[1]
    nonce = blob[2:14]
    wraps = blob[14:14 + 48 * count]
    payload = blob[14 + 48 * count:]
    header = blob[1:14 + 48 * count]
    key = wrap_key(secret)
    for i in range(count):
        try:
            content_key = ChaCha20Poly1305(key).decrypt(nonce_at(nonce, i + 1), wraps[48 * i:48 * i + 48], aad(PURPOSE_WRAP, salt, seq, b""))
        except Exception:
            continue
        return ChaCha20Poly1305(content_key).decrypt(nonce_at(nonce, 0), payload, aad(PURPOSE_CONTENT, salt, seq, header))
    raise ValueError("no wrap opens")


if __name__ == "__main__":
    salt = b"velora/1"
    seq = 1_700_000_000
    secrets = [bytes([0x11]) * 16, bytes([0x12]) * 16]
    blob = seal(b"hello velora", salt, seq, secrets, bytes([0x22]) * 32, bytes([0x33]) * 12)
    print(len(blob), blob.hex())
    if len(sys.argv) > 1:
        rust = bytes.fromhex(sys.argv[1])
        print("same bytes as the Rust seal:", rust == blob)
        for s in secrets:
            print("python opens the Rust blob:", open_(rust, salt, seq, s))
        try:
            open_(rust, salt, seq + 1, secrets[0])
            print("UNEXPECTED: opened under another seq")
        except ValueError:
            print("another seq does not open: ok")
