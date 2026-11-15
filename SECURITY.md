# SECURITY.md — Security Analysis

**CS5.470 System and Network Security | Lab Assignment 3**
*Kerberos Under Partial Compromise using Schnorr Multi-Signatures*

---

## 1. Why One Compromised Authority Cannot Forge Tickets

### The Core Argument

A valid ticket requires **at least two independent Schnorr signatures** from
*different* authorities, each verified using that authority's known public key.

A Schnorr signature `(R, s)` over message `m` for authority `i` satisfies:

```
g^s ≡ R · y_i^{e_i}  mod p
where  e_i = H(m || R || ID_i)  mod q
```

For an adversary who has compromised authority `i` (and thus knows `x_i`), they
can produce valid `(R_i, s_i)` — but this gives them **exactly one** valid
signature.  To pass the 2-of-3 threshold they need a valid signature from some
other authority `j`, which requires knowing `x_j`.

**Producing a valid Schnorr signature without knowing the private key reduces to
computing a discrete logarithm in a 2048-bit prime-order group** — believed to
require sub-exponential but astronomically large effort (≫ 2^112 operations).

Therefore: **one compromised authority → one valid signature → threshold not met
→ ticket rejected**.

---

## 2. Why Two Compromised Authorities Break Security

If an adversary controls authorities `i` and `j`, they know both `x_i` and
`x_j`.  They can now:

1. Choose any ticket payload `m` (even fraudulent).
2. Generate valid `(R_i, s_i)` for authority `i`.
3. Generate valid `(R_j, s_j)` for authority `j`.
4. Assemble a ticket with two valid signatures — the threshold is met.

This ticket will **pass all verification checks** at every service server
and TGS node, because each of the two signatures is cryptographically valid.

**Conclusion**: The 2-of-3 Schnorr multi-signature scheme provides security
against compromise of *any one* authority but **not** against compromise of
two or more.  The *t*-of-*n* threshold must always satisfy `t > n/2` to
tolerate a minority of malicious parties; 2-of-3 achieves exactly this.

---

## 3. Why Two Independent Schnorr Signatures Prevent a Single
## Compromised Authority from Forging Tickets

Two properties are critical:

### 3.1 Binding to the signer's public key

Each signature is verified against the corresponding public key `y_i = g^{x_i}`.
A compromised authority `i` can forge signatures **only for identity `i`**.
Trying to forge a signature under identity `j` while passing it off as `(R, s)`
for `y_j` requires finding `s` such that `g^s ≡ R · y_j^e mod p`, which is
equivalent to knowing `x_j` (discrete log assumption).

### 3.2 Independent signatures over the same payload

Both signatures are computed over the **same canonical payload bytes**
(deterministically serialised including timestamp, client_id, etc.).  The
challenge for each signature is:

```
e_i = H(payload_bytes || R_i || ID_i)  mod q
```

The inclusion of `ID_i` in the challenge hash **binds** the signature to a
specific authority identity.  Even if the adversary reuses `R_i` under a
different `ID_j`, the challenge value changes, making the response `s` invalid
for the new identity.

### 3.3 No aggregation — independent verification

This system does **not** use MuSig or key aggregation.  Each signature is
verified independently.  This avoids rogue-key attacks and simplifies the
security argument: each signature is a stand-alone Schnorr proof of knowledge
of the signer's private key over the payload.

---

## 4. Nonce Reuse Risks

The Schnorr scheme is **catastrophically broken** if the same nonce `k` is
used for two different messages.

**Attack** (nonce reuse across two messages `m_1`, `m_2`):

```
s_1 = k + e_1 * x  mod q
s_2 = k + e_2 * x  mod q

s_1 - s_2 = (e_1 - e_2) * x  mod q
x = (s_1 - s_2) * (e_1 - e_2)^{-1}  mod q
```

If `e_1 ≠ e_2` (guaranteed when `m_1 ≠ m_2`) and `k` is shared, the private
key `x` is recovered in a single modular arithmetic operation.

**Mitigation in this implementation**:

- Every call to `schnorr_sign()` draws a fresh `k` from `os.urandom(32)`.
- Python's `os.urandom` is backed by the kernel CSPRNG (`/dev/urandom` on
  Linux, `BCryptGenRandom` on Windows).
- The nonce `k` is **never stored or logged**.
- There is no code path that allows reuse.

**Consequence of violation**: Full private key recovery with a single pair of
signatures — the entire multi-authority guarantee collapses for that authority.

---

## 5. Key Share Leakage Impact

### Single key leaked (`x_i`)

The adversary can:
- Sign arbitrary messages as authority `i`.
- Produce one valid Schnorr signature per ticket.

The adversary **cannot**:
- Forge signatures for authorities `j ≠ i`.
- Meet the 2-of-3 threshold alone.

**Impact**: Partial — one authority is effectively corrupted.  Security
reduces to 1-of-2 remaining authorities, which still provides the threshold.
Tickets for existing users remain secure.  **Immediate remediation**: rotate
all keys using `python master_keygen.py --force`.

### Two keys leaked (`x_i` and `x_j`)

The adversary can produce two valid independent signatures → full ticket
forgery for any client, any service, any timestamp.  **This breaks the system**.

### All three keys leaked

Complete system compromise.

### Key rotation

After any suspected leakage:
1. Run `python master_keygen.py --force` to generate new keys.
2. The `key_version` counter increments.
3. All nodes reload keys on startup.
4. Old tickets (with lower `key_version`) are rejected by TGS and service
   servers — preventing replay of tickets issued under the old compromised key.

---

## 6. Performance Overhead of Multi-Authority Signing

### Crypto cost per ticket

| Operation | Group ops | Approx. time |
|-----------|-----------|-------------|
| `schnorr_sign` | 1 modexp (2048-bit) | ~50 ms |
| `schnorr_verify` | 2 modexp (2048-bit) | ~100 ms |
| Phase 1 (3 signs, 3 verifies, parallel) | 15 modexps | ~150–300 ms |
| Phase 2 (3 signs, 3 verifies, parallel) | 15 modexps | ~150–300 ms |

### Compared to classical Kerberos

Classical Kerberos uses a single AS/TGS with symmetric encryption — nearly
instantaneous.  The multi-signature system adds:

- **~3–6× latency** for authentication phases.
- **~6× more CPU** per authentication.
- **Network parallelism** (all 3 nodes contacted concurrently) significantly
  reduces wall-clock latency vs. serial contact.

### Optimisations possible but not implemented

- Use a **256-bit elliptic curve** (e.g., Curve25519) instead of a 2048-bit
  multiplicative group — 10–50× faster modular arithmetic.
- **Pre-compute** `y^e` using a sliding-window or NAF representation.
- Cache public key precomputation tables for batch verification.

### Bandwidth overhead

Each `(R, s)` pair is a 2048-bit + 256-bit value ≈ 288 bytes.  Two signatures
add ~576 bytes per ticket — negligible on any modern network.

---

## 7. Threat Model Recap

| Threat | Protected? | Mechanism |
|--------|-----------|-----------|
| One malicious AS | ✅ Yes | 2-of-3 threshold |
| One malicious TGS | ✅ Yes | 2-of-3 threshold |
| Ticket payload tampering | ✅ Yes | Signature binds payload |
| Replay of old signatures | ✅ Yes | Payload includes timestamp |
| Single key leakage | ✅ Yes | Need 2 keys to forge |
| Two authorities compromised | ❌ No | Exceeds threshold tolerance |
| AES key brute-force | ✅ Yes | 256-bit key space |
| DLP (discrete log) break | ❌ No* | Hardness assumption |

*If DLP is broken (e.g., by a quantum computer running Shor's algorithm), all
discrete-log-based cryptography including Schnorr fails.  Post-quantum
alternatives (e.g., Dilithium lattice signatures) would be needed.

---

## 8. Summary

The 2-of-3 Schnorr multi-signature design provides:

- **Fault tolerance**: any single authority can be offline without service disruption.
- **Partial compromise resilience**: a single compromised authority cannot forge tickets.
- **Tamper evidence**: any modification to a signed ticket is detectable.
- **Replay prevention**: per-request timestamps bound signatures to specific instants.
- **Key version enforcement**: revoked keys are rejected system-wide.

The system does **not** protect against compromise of two or more authorities,
quantum adversaries, or side-channel attacks on key material.
