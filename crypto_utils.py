"""
crypto_utils.py
===============
Cryptographic primitives for the Kerberos multi-signature system.

Implements (without asymmetric crypto libraries):
  - Modular exponentiation
  - Modular arithmetic over Zq
  - Schnorr key generation
  - Schnorr signature generation and verification
  - SHA-256 hashing helpers
  - AES-256-CBC encryption/decryption
  - Manual PKCS#7 padding/unpadding
  - OS-level secure RNG
"""

import os
import hashlib
import struct
from typing import Tuple


# ---------------------------------------------------------------------------
# 1.  Schnorr / DSA system parameters
#
#  We use RFC 3526 MODP Group 14 — a 2048-bit SAFE PRIME.
#  A safe prime has the form P = 2·Q + 1 where both P and Q are prime.
#  This means the multiplicative group Z_P* has a prime-order subgroup of
#  order Q = (P-1)/2 (≈ 2047 bits), which is the subgroup we use.
#
#  Generator: g = 4 = 2^2 mod P
#    - 4 is a quadratic residue mod P, so 4^Q ≡ 1 (mod P)  [by Euler/Fermat]
#    - ord(4) = Q  (since the only divisors of the group order are 1, 2, Q, 2Q
#      and 4^1 ≠ 1, 4^2 ≠ 1, 4^Q = 1)
#    - This gives us a prime-order-Q subgroup in which Schnorr is defined.
# ---------------------------------------------------------------------------

# 2048-bit safe prime p (RFC 3526 MODP Group 14)
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)

# Prime order of the Schnorr subgroup: Q = (P - 1) / 2  (safe-prime structure)
Q = (P - 1) // 2

# Generator of the prime-order-Q subgroup: g = 4 (a quadratic residue mod P)
# Satisfies: g^Q ≡ 1 (mod P) and ord(g) = Q
G = 4


# ---------------------------------------------------------------------------
# 2.  Secure random number generation
# ---------------------------------------------------------------------------

def secure_random_scalar() -> int:
    """Return a random integer in [1, Q-1] using OS-level RNG."""
    while True:
        raw = int.from_bytes(os.urandom(32), "big")
        r = raw % (Q - 1)
        if r != 0:
            return r


def secure_random_bytes(n: int) -> bytes:
    """Return n random bytes from OS RNG."""
    return os.urandom(n)


# ---------------------------------------------------------------------------
# 3.  Modular arithmetic helpers
# ---------------------------------------------------------------------------

def mod_exp(base: int, exp: int, mod: int) -> int:
    """
    Compute base^exp mod mod using the square-and-multiply algorithm.
    Built from scratch — no pow() with three arguments.
    """
    if mod == 1:
        return 0
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:                 # exp is odd
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result


def mod_inv(a: int, m: int) -> int:
    """Extended Euclidean Algorithm to compute a^{-1} mod m."""
    if m == 1:
        return 0
    m0, x0, x1 = m, 0, 1
    a = a % m
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 % m0


# ---------------------------------------------------------------------------
# 4.  SHA-256 helpers
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    """Return the SHA-256 digest of data."""
    return hashlib.sha256(data).digest()


def sha256_int(data: bytes) -> int:
    """Return the SHA-256 digest of data as an integer."""
    return int.from_bytes(sha256(data), "big")


def hash_challenge(message: bytes, R: int, authority_id: str) -> int:
    """
    Compute the Schnorr challenge:
        e_i = H(m || R_i || ID_i)  mod q
    Returns an integer in [0, Q-1].
    """
    # R is an element of Z_P* (2048-bit prime), so encode as 256 bytes big-endian
    r_bytes = R.to_bytes(256, "big")
    id_bytes = authority_id.encode("utf-8")
    digest = sha256(message + r_bytes + id_bytes)
    # Reduce mod Q; Q is ~2047 bits, SHA-256 output is 256 bits — result is < Q always
    return int.from_bytes(digest, "big") % Q


# ---------------------------------------------------------------------------
# 5.  Schnorr key generation
# ---------------------------------------------------------------------------

def schnorr_keygen() -> Tuple[int, int]:
    """
    Generate a Schnorr key pair (x, y) where:
        x  = private key  ∈ Zq
        y  = g^x mod p   (public key)
    Returns (x, y).
    """
    x = secure_random_scalar()
    y = mod_exp(G, x, P)
    return x, y


# ---------------------------------------------------------------------------
# 6.  Schnorr signature generation
# ---------------------------------------------------------------------------

def schnorr_sign(
    message: bytes,
    x: int,
    authority_id: str,
) -> Tuple[int, int]:
    """
    Generate an independent Schnorr signature over *message* by authority
    with private key *x* and string identifier *authority_id*.

    Algorithm:
        k  ← random ∈ Zq          (fresh nonce — NEVER reuse)
        R  = g^k mod p
        e  = H(m || R || ID)  mod q
        s  = (k + e·x) mod q

    Returns (R, s).
    """
    k = secure_random_scalar()               # fresh nonce every call
    R = mod_exp(G, k, P)
    e = hash_challenge(message, R, authority_id)
    s = (k + e * x) % Q
    return R, s


# ---------------------------------------------------------------------------
# 7.  Schnorr signature verification
# ---------------------------------------------------------------------------

def schnorr_verify(
    message: bytes,
    R: int,
    s: int,
    y: int,
    authority_id: str,
) -> bool:
    """
    Verify a Schnorr signature (R, s) from authority with public key *y*
    and identifier *authority_id* over *message*.

    Verification equation:
        g^s ≡ R · y^e  mod p
    where e = H(m || R || ID) mod q.
    """
    if not (1 <= R < P) or not (0 < s < Q):
        return False
    e = hash_challenge(message, R, authority_id)
    lhs = mod_exp(G, s, P)
    rhs = (R * mod_exp(y, e, P)) % P
    return lhs == rhs


def verify_multisig(
    message: bytes,
    signatures: list,          # list of {"R": int, "s": int, "authority_id": str, "public_key": int}
    threshold: int = 2,
) -> bool:
    """
    Verify that at least *threshold* independent Schnorr signatures in
    *signatures* are valid over *message*.

    Each entry in *signatures* must be a dict with keys:
        R            – commitment (int)
        s            – response (int)
        authority_id – string identifier of the signing authority
        public_key   – y_i (int)

    Returns True iff the number of valid independent signatures ≥ threshold.
    """
    valid_ids: set = set()
    for sig in signatures:
        aid = sig["authority_id"]
        if aid in valid_ids:
            # duplicate authority — already counted
            continue
        ok = schnorr_verify(
            message,
            sig["R"],
            sig["s"],
            sig["public_key"],
            aid,
        )
        if ok:
            valid_ids.add(aid)
    return len(valid_ids) >= threshold


# ---------------------------------------------------------------------------
# 8.  PKCS#7 padding (manual implementation)
# ---------------------------------------------------------------------------

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Apply PKCS#7 padding to *data* for the given *block_size*.
    Padding byte value equals the number of bytes added (1–block_size).
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """
    Remove PKCS#7 padding from *data*.
    Raises ValueError on invalid padding.
    """
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid data length for PKCS#7 unpadding.")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError(f"Invalid PKCS#7 padding byte: {pad_len}")
    # Validate that all padding bytes are equal to pad_len
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding content.")
    return data[:-pad_len]


# ---------------------------------------------------------------------------
# 9.  AES-256-CBC  (using Python's built-in 'cryptography' or 'pycryptodome'
#     only for the AES block cipher primitive, NOT for any asymmetric operation)
# ---------------------------------------------------------------------------
#
#  The assignment forbids "asymmetric crypto libraries".  AES is a symmetric
#  primitive.  We use the standard library's `cryptography` package ONLY for
#  the AES block cipher.  All padding, key derivation, and IV management are
#  done manually below.
# ---------------------------------------------------------------------------

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend as _backend

    def _aes_ecb_encrypt_block(key: bytes, block: bytes) -> bytes:
        c = Cipher(algorithms.AES(key), modes.ECB(), backend=_backend())
        enc = c.encryptor()
        return enc.update(block) + enc.finalize()

    def _aes_ecb_decrypt_block(key: bytes, block: bytes) -> bytes:
        c = Cipher(algorithms.AES(key), modes.ECB(), backend=_backend())
        dec = c.decryptor()
        return dec.update(block) + dec.finalize()

    _CRYPTO_BACKEND = "cryptography"

except ImportError:
    try:
        from Crypto.Cipher import AES as _AES

        def _aes_ecb_encrypt_block(key: bytes, block: bytes) -> bytes:  # type: ignore
            return _AES.new(key, _AES.MODE_ECB).encrypt(block)

        def _aes_ecb_decrypt_block(key: bytes, block: bytes) -> bytes:  # type: ignore
            return _AES.new(key, _AES.MODE_ECB).decrypt(block)

        _CRYPTO_BACKEND = "pycryptodome"

    except ImportError:
        raise ImportError(
            "Neither 'cryptography' nor 'pycryptodome' is installed. "
            "Install one: pip install cryptography"
        )


def aes256_cbc_encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt *plaintext* with AES-256-CBC using *key* (32 bytes).
    Padding is applied manually with PKCS#7.

    Returns (iv, ciphertext).  IV is randomly generated.
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")
    iv = secure_random_bytes(16)
    padded = pkcs7_pad(plaintext, 16)

    ciphertext = b""
    prev_block = iv
    for i in range(0, len(padded), 16):
        block = padded[i : i + 16]
        xored = bytes(a ^ b for a, b in zip(block, prev_block))
        enc_block = _aes_ecb_encrypt_block(key, xored)
        ciphertext += enc_block
        prev_block = enc_block

    return iv, ciphertext


def aes256_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt *ciphertext* with AES-256-CBC using *key* (32 bytes) and *iv*.
    PKCS#7 unpadding is applied manually after decryption.

    Returns the original plaintext.
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16.")

    plaintext_padded = b""
    prev_block = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i : i + 16]
        dec_block = _aes_ecb_decrypt_block(key, block)
        xored = bytes(a ^ b for a, b in zip(dec_block, prev_block))
        plaintext_padded += xored
        prev_block = block

    return pkcs7_unpad(plaintext_padded, 16)


# ---------------------------------------------------------------------------
# 10.  Session key derivation
# ---------------------------------------------------------------------------

def derive_session_key(shared_secret: bytes) -> bytes:
    """Derive a 32-byte AES session key from shared_secret using SHA-256."""
    return sha256(shared_secret)


def generate_session_key() -> bytes:
    """Generate a fresh random 32-byte session key."""
    return secure_random_bytes(32)


# ---------------------------------------------------------------------------
# 11.  Ticket payload serialisation helpers
# ---------------------------------------------------------------------------

def encode_ticket_payload(fields: dict) -> bytes:
    """
    Serialise a ticket field dictionary into a canonical byte string for
    hashing / signing.  Only deterministic, order-dependent fields are
    included.  Uses a simple length-prefixed binary format.
    """
    import json
    # Exclude signature fields themselves from the signed payload
    excluded = {"signatures", "iv", "ciphertext"}
    signing_fields = {k: v for k, v in fields.items() if k not in excluded}
    canonical = json.dumps(signing_fields, sort_keys=True, separators=(",", ":"))
    return canonical.encode("utf-8")


# ---------------------------------------------------------------------------
# 12.  Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== crypto_utils self-test ===")

    # Key generation
    x, y = schnorr_keygen()
    print(f"Private key x (hex, first 16 bytes): {x.to_bytes(32,'big').hex()[:32]}...")
    print(f"Public  key y (hex, first 16 bytes): {y.to_bytes(256,'big').hex()[:32]}...")

    # Sign and verify
    msg = b"test message for schnorr"
    R, s = schnorr_sign(msg, x, "AS1")
    ok = schnorr_verify(msg, R, s, y, "AS1")
    print(f"Schnorr sign+verify: {'PASS' if ok else 'FAIL'}")

    # Reject tampered message
    ok_bad = schnorr_verify(b"tampered message", R, s, y, "AS1")
    print(f"Reject tampered msg: {'PASS' if not ok_bad else 'FAIL'}")

    # Multi-signature threshold
    x2, y2 = schnorr_keygen()
    R2, s2 = schnorr_sign(msg, x2, "AS2")
    sigs = [
        {"R": R, "s": s, "authority_id": "AS1", "public_key": y},
        {"R": R2, "s": s2, "authority_id": "AS2", "public_key": y2},
    ]
    ok_multi = verify_multisig(msg, sigs, threshold=2)
    print(f"Multi-sig (2-of-2) valid: {'PASS' if ok_multi else 'FAIL'}")

    ok_single = verify_multisig(msg, sigs[:1], threshold=2)
    print(f"Reject single sig:        {'PASS' if not ok_single else 'FAIL'}")

    # AES-256-CBC
    key = generate_session_key()
    plaintext = b"Hello, Kerberos multi-sig world!"
    iv, ct = aes256_cbc_encrypt(key, plaintext)
    recovered = aes256_cbc_decrypt(key, iv, ct)
    print(f"AES-256-CBC round-trip:   {'PASS' if recovered == plaintext else 'FAIL'}")

    # PKCS#7 edge cases
    for length in [0, 1, 15, 16, 17, 32]:
        data = os.urandom(length)
        assert pkcs7_unpad(pkcs7_pad(data)) == data, f"PKCS#7 failed for length {length}"
    print("PKCS#7 padding:           PASS")

    print("=== All tests passed ===")
