"""Searching the database: byte patterns, immediates, text, strings, crypto."""

from __future__ import annotations

from typing import Iterator

import ida_bytes
import ida_ida
import ida_idaapi

BADADDR = ida_idaapi.BADADDR


def compile_bytes(pattern: str) -> ida_bytes.compiled_binpat_vec_t:
    """Compile an IDA binary pattern ("55 8B EC ?? 83" or "558BEC??83")."""
    text = pattern.strip()
    if " " not in text and len(text) % 2 == 0:
        text = " ".join(text[i:i + 2] for i in range(0, len(text), 2))
    vec = ida_bytes.compiled_binpat_vec_t()
    err = ida_bytes.parse_binpat_str(vec, ida_ida.inf_get_min_ea(), text, 16)
    if err is False or err is None and vec.empty():
        from ..errors import Exit, IcliError

        raise IcliError(Exit.USAGE, f"bad byte pattern {pattern!r}", "USAGE")
    return vec


def find_bytes(pattern: str, start: int | None = None, end: int | None = None) -> Iterator[int]:
    vec = compile_bytes(pattern)
    ea = ida_ida.inf_get_min_ea() if start is None else start
    hi = ida_ida.inf_get_max_ea() if end is None else end
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK | ida_bytes.BIN_SEARCH_NOSHOW
    while ea < hi:
        found = ida_bytes.bin_search(ea, hi, vec, flags)
        if isinstance(found, tuple):
            found = found[0]
        if found == BADADDR or found >= hi:
            return
        yield found
        ea = found + 1


# -- known cryptographic constants ------------------------------------------------------

def _u32le(*words: int) -> bytes:
    return b"".join(w.to_bytes(4, "little") for w in words)


def _u32be(*words: int) -> bytes:
    return b"".join(w.to_bytes(4, "big") for w in words)


_AES_SBOX_HEAD = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0")
_AES_INV_SBOX_HEAD = bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb")
_SHA256_K = (0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5)
_SHA256_H = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
_SHA1_H = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
_MD5_T = (0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A)
_CRC32_TABLE = (0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F)
_BLOWFISH_P = (0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0)
_SHA512_H = bytes.fromhex("6a09e667f3bcc908bb67ae8584caa73b")

CRYPTO: list[tuple[str, bytes]] = [
    ("AES_sbox", _AES_SBOX_HEAD),
    ("AES_inv_sbox", _AES_INV_SBOX_HEAD),
    ("SHA256_K", _u32le(*_SHA256_K)), ("SHA256_K_be", _u32be(*_SHA256_K)),
    ("SHA256_init", _u32le(*_SHA256_H)), ("SHA256_init_be", _u32be(*_SHA256_H)),
    ("SHA1_init", _u32le(*_SHA1_H)), ("SHA1_init_be", _u32be(*_SHA1_H)),
    ("MD5_T", _u32le(*_MD5_T)), ("MD5_T_be", _u32be(*_MD5_T)),
    ("CRC32_table", _u32le(*_CRC32_TABLE)), ("CRC32_table_be", _u32be(*_CRC32_TABLE)),
    ("Blowfish_P", _u32le(*_BLOWFISH_P)), ("Blowfish_P_be", _u32be(*_BLOWFISH_P)),
    ("SHA512_init_be", _SHA512_H),
    ("ChaCha_sigma", b"expand 32-byte k"),
    ("Salsa_tau", b"expand 16-byte k"),
]

# 32-bit immediates that identify an algorithm when used as instruction operands
CRYPTO_IMMEDIATES: dict[int, str] = {
    0x9E3779B9: "TEA_delta", 0x61C88647: "TEA_delta_neg", 0x67452301: "MD5_SHA1_init_A",
    0xEFCDAB89: "MD5_SHA1_init_B", 0x6A09E667: "SHA256_init_A", 0xEDB88320: "CRC32_poly_reflected",
    0x04C11DB7: "CRC32_poly", 0x5A827999: "SHA1_K1", 0x6ED9EBA1: "SHA1_K2", 0xD76AA478: "MD5_T1",
}


def find_raw(data: bytes, start: int | None = None, end: int | None = None) -> Iterator[int]:
    """Exact byte-string search over the database."""
    return find_bytes(data.hex(), start, end)
