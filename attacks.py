"""
attacks.py
==========
Mandatory Attack Scenario Demonstrations for the Kerberos Multi-Sig System.

All six attacks run against REAL, live AS / TGS / Service server instances
that are started in-process as background threads before the scenarios begin.
This means every attack exercises the full TCP protocol stack — not just local
crypto — so the results reflect what an adversary would actually see.

Six attack scenarios as required by the assignment:

  1. Single malicious authority issuing a forged ticket
     → Adversary uses AS1's compromised key to sign on behalf of both AS1 and
       AS2.  The forged AS2 signature is verified against AS2's real public key
       and fails.  The TGS therefore rejects the TGT (< 2 valid sigs).

  2. Modified ticket payload (tampering attack)
     → A legitimately obtained TGT has its client_id swapped from "ishaan" to
       "admin".  The TGS verifies the multi-sig over the tampered bytes and
       rejects it.

  3. Replay of an old partial signature
     → An old AS1 signature (captured 2 hours ago) is spliced into a fresh TGT
       request.  The AS1 sig was created over a different timestamp, so Schnorr
       verification fails on the new payload.  The TGS rejects the TGT.

  4. Leakage of one authority's private signing key
     → AS1's private key is leaked.  The adversary can forge a valid AS1 sig but
       must still forge AS2's sig without AS2's key (random forgery).  The TGS
       verifies both and rejects (only 1 valid sig).

  5. Authority offline scenario (fault-tolerance + degradation attack)
     → Sub-A: AS3 offline — client collects 2 valid sigs (AS1, AS2).  Full flow
       succeeds; service grants access.
     → Sub-B: AS2 and AS3 offline — only 1 valid sig.  TGS rejects the TGT.

  6. Ticket containing only one valid signature
     → A TGT is manually crafted with one real AS1 signature and one garbage
       AS2 entry.  The TGS rejects it (< 2 valid sigs).

Each scenario:
  - Uses the live servers for all verification steps.
  - Prints a clear PASS / FAIL result with a security explanation.

Usage:
    python attacks.py              # run all scenarios (auto-starts servers)
    python attacks.py --scenario 1 # run a specific scenario
    python attacks.py --no-servers # skip server startup (servers already running)
"""

import json
import os
import sys
import time
import socket
import threading
import argparse

sys.path.insert(0, os.path.dirname(__file__))

from crypto_utils import (
    schnorr_keygen,
    schnorr_sign,
    schnorr_verify,
    verify_multisig,
    generate_session_key,
    aes256_cbc_encrypt,
    aes256_cbc_decrypt,
    sha256,
    encode_ticket_payload,
    P, Q, G,
    mod_exp,
    secure_random_scalar,
)
from master_keygen import load_system_params, load_authority_private_key

# ─────────────────────────────────────────────────────────────────────────────
# Formatting helpers
# ─────────────────────────────────────────────────────────────────────────────

SEPARATOR = "─" * 65


def print_header(number: int, title: str) -> None:
    print(f"\n{'=' * 65}")
    print(f"  Attack {number}: {title}")
    print(f"{'=' * 65}")


def print_result(passed: bool, explanation: str) -> None:
    status = " DEFENDED" if passed else " VULNERABLE"
    print(f"\nResult : {status}")
    print(f"Reason : {explanation}")
    print(SEPARATOR)


# ─────────────────────────────────────────────────────────────────────────────
# TCP helper (mirrors client.py)
# ─────────────────────────────────────────────────────────────────────────────

HOST = "127.0.0.1"


def tcp_send_recv(port: int, payload: dict, timeout: float = 15.0) -> dict:
    """Send a JSON request and receive a JSON response (newline-delimited)."""
    with socket.create_connection((HOST, port), timeout=timeout) as s:
        s.sendall(json.dumps(payload).encode() + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    return json.loads(data.decode().strip())


# ─────────────────────────────────────────────────────────────────────────────
# Inline server launchers
# ─────────────────────────────────────────────────────────────────────────────

def _start_servers() -> None:
    """
    Start AS1-3, TGS1-3, and the Service server as daemon threads so that
    attacks.py is fully self-contained and does not require external terminals.
    """
    import as_node
    import tgs_node
    import service_server

    params = load_system_params()

    for aid in ("AS1", "AS2", "AS3"):
        t = threading.Thread(target=as_node.run_as_node, args=(aid,), daemon=True)
        t.start()

    for tid in ("TGS1", "TGS2", "TGS3"):
        t = threading.Thread(target=tgs_node.run_tgs_node, args=(tid,), daemon=True)
        t.start()

    t = threading.Thread(target=service_server.run_service_server, daemon=True)
    t.start()

    # Give servers a moment to bind their sockets
    time.sleep(1.5)
    print("[setup] All server threads started (AS1-3, TGS1-3, SERVICE).\n")


def _servers_already_up(params: dict) -> bool:
    """Return True if at least AS1 is already listening."""
    try:
        s = socket.create_connection((HOST, params["ports"]["AS1"]), timeout=0.5)
        s.close()
        return True
    except OSError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Protocol helpers shared across attacks
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_PASSWORDS = {
    "ishaan":   "password_ishaan",
    # "ishaan":  "password_ishaan",
    "ankit":   "password_ankit",
    "vipin":   "password_vipin",
}


def derive_client_key(client_id: str, password: str) -> bytes:
    raw = (password + ":" + client_id).encode("utf-8")
    return sha256(raw)


def _get_real_tgt(client_id: str = "ishaan",
                  service_id: str = "file_service",
                  exclude_as: list = None) -> dict:  # type: ignore[assignment]
    """
    Obtain a real multi-signature TGT from the live AS cluster.

    Parameters
    ----------
    client_id  : username to authenticate
    exclude_as : list of AS IDs to skip (simulate offline nodes)

    Returns the TGT dict (payload + signatures + tgt_session_key_enc).
    """
    params   = load_system_params()
    password = DEFAULT_PASSWORDS.get(client_id, "password_" + client_id)
    exclude  = set(exclude_as or [])

    as_nodes = {
        aid: params["ports"][aid]
        for aid in ("AS1", "AS2", "AS3")
        if aid not in exclude
    }

    request = {
        "type":      "AUTH_REQUEST",
        "client_id": client_id,
        "tgs_id":    "TGS",
        "timestamp": time.time(),
    }

    responses = {}
    for aid, port in as_nodes.items():
        try:
            resp = tcp_send_recv(port, request)
            responses[aid] = resp
        except Exception as e:
            print(f"  [AS] {aid} unreachable: {e}")

    client_key = derive_client_key(client_id, password)
    valid_sigs = []
    ticket_payload = None
    chosen_enc = None

    for aid, resp in responses.items():
        if resp.get("status") != "OK":
            continue
        tp      = resp["ticket_payload"]
        sig_raw = resp["signature"]
        pk      = int(resp["public_key"], 16)
        R       = int(sig_raw["R"], 16)
        s       = int(sig_raw["s"], 16)

        payload_bytes = encode_ticket_payload(tp)
        if not schnorr_verify(payload_bytes, R, s, pk, aid):
            print(f"  [AS] {aid} signature invalid — discarding")
            continue

        valid_sigs.append({
            "R":            hex(R),
            "s":            hex(s),
            "authority_id": aid,
            "public_key":   hex(pk),
        })
        ticket_payload = tp
        if chosen_enc is None:
            chosen_enc = resp["session_key_encrypted"]

    return {
        "payload":             ticket_payload,
        "signatures":          valid_sigs,
        "tgt_session_key_enc": chosen_enc,
        "_valid_sig_count":    len(valid_sigs),   # internal bookkeeping
    }


def _submit_tgt_to_tgs(tgt: dict,
                        client_id: str = "ishaan",
                        service_id: str = "file_service",
                        tgs_id: str = "TGS1") -> dict:
    """
    Submit a (possibly tampered) TGT to a single TGS node and return the
    raw response dict.
    """
    params = load_system_params()
    port   = params["ports"][tgs_id]

    # Strip internal bookkeeping before sending
    wire_tgt = {k: v for k, v in tgt.items() if not k.startswith("_")}

    request = {
        "type":       "TGS_REQUEST",
        "client_id":  client_id,
        "service_id": service_id,
        "timestamp":  time.time(),
        "tgt":        wire_tgt,
    }
    return tcp_send_recv(port, request)


def _collect_service_ticket(tgt: dict,
                             client_id: str = "ishaan",
                             service_id: str = "file_service"):  # -> dict | None
    """
    Contact all three TGS nodes with *tgt*, collect ≥2 valid service-ticket
    signatures, and return a ready-to-submit service ticket.
    Returns None if fewer than 2 TGS nodes accept the TGT.
    """
    params   = load_system_params()
    tgs_nodes = {
        "TGS1": params["ports"]["TGS1"],
        "TGS2": params["ports"]["TGS2"],
        "TGS3": params["ports"]["TGS3"],
    }

    wire_tgt = {k: v for k, v in tgt.items() if not k.startswith("_")}
    request  = {
        "type":       "TGS_REQUEST",
        "client_id":  client_id,
        "service_id": service_id,
        "timestamp":  time.time(),
        "tgt":        wire_tgt,
    }

    valid_sigs          = []
    service_ticket_payload = None
    service_session_key = None

    for aid, port in tgs_nodes.items():
        try:
            resp = tcp_send_recv(port, request)
        except Exception as e:
            print(f"  [TGS] {aid} unreachable: {e}")
            continue

        if resp.get("status") != "OK":
            print(f"  [TGS] {aid} rejected TGT: {resp.get('message')}")
            continue

        tp      = resp["ticket_payload"]
        sig_raw = resp["signature"]
        pk      = int(resp["public_key"], 16)
        R       = int(sig_raw["R"], 16)
        s       = int(sig_raw["s"], 16)

        payload_bytes = encode_ticket_payload(tp)
        if not schnorr_verify(payload_bytes, R, s, pk, aid):
            print(f"  [TGS] {aid} service-ticket signature invalid — discarding")
            continue

        # Decrypt service session key
        ssk_enc       = resp["enc_service_session_key"]
        tgt_enc_bytes = (
            bytes.fromhex(tgt["tgt_session_key_enc"]["iv"]) +
            bytes.fromhex(tgt["tgt_session_key_enc"]["ciphertext"])
        )
        tgs_key = sha256(tgt_enc_bytes)
        try:
            ssk = aes256_cbc_decrypt(
                tgs_key,
                bytes.fromhex(ssk_enc["iv"]),
                bytes.fromhex(ssk_enc["ciphertext"]),
            )
            if service_session_key is None:
                service_session_key = ssk
        except Exception as e:
            print(f"  [TGS] {aid} service-session-key decrypt failed: {e}")
            continue

        valid_sigs.append({
            "R":            hex(R),
            "s":            hex(s),
            "authority_id": aid,
            "public_key":   hex(pk),
        })
        service_ticket_payload = tp

    if len(valid_sigs) < 2:
        return None

    assert service_ticket_payload is not None
    svc_payload_bytes = encode_ticket_payload(service_ticket_payload)
    svc_key           = sha256(b"SERVICE" + svc_payload_bytes)
    iv_svc, ct_svc    = aes256_cbc_encrypt(svc_key, service_session_key or b"\x00" * 32)

    return {
        "payload":    service_ticket_payload,
        "signatures": valid_sigs,
        "iv":         iv_svc.hex(),
        "ciphertext": ct_svc.hex(),
    }


def _submit_service_ticket(service_ticket: dict,
                            client_id: str = "ishaan",
                            service_id: str = "file_service") -> dict:
    """Submit a service ticket to the Service server and return the response."""
    params = load_system_params()
    port   = params["ports"]["SERVICE"]

    request = {
        "type":           "SERVICE_REQUEST",
        "client_id":      client_id,
        "service_id":     service_id,
        "timestamp":      time.time(),
        "service_ticket": service_ticket,
    }
    return tcp_send_recv(port, request)


# ─────────────────────────────────────────────────────────────────────────────
# Attack 1 — Single Malicious Authority Issuing a Forged Ticket
# ─────────────────────────────────────────────────────────────────────────────

def attack1_single_malicious_authority() -> bool:
    """
    Scenario
    --------
    AS1 is fully compromised.  The adversary uses AS1's private key to craft
    a TGT and signs it TWICE — once claiming to be AS1, once claiming to be
    AS2 — hoping to satisfy the 2-of-3 threshold with only one real key.

    The forged TGT is submitted to the live TGS cluster (TGS1-3).

    Expected outcome
    ----------------
    DEFENDED — the second signature was produced with AS1's key but is verified
    against AS2's (different) public key; verification fails.  The TGS counts
    only 1 valid unique signature, which is below the threshold.
    """
    print_header(1, "Single Malicious Authority Issuing Forged Ticket")

    params     = load_system_params()
    public_keys = params["public_keys"]

    x1, y1, _ = load_authority_private_key("AS1")   # compromised key

    payload = {
        "client_id":   "ishaan",
        "tgs_id":      "TGS",
        "timestamp":   time.time(),
        "lifetime":    3600,
        "key_version": params["key_version"],
    }
    payload_bytes = encode_ticket_payload(payload)

    # Sign with AS1 key, claim identity AS1
    R1, s1 = schnorr_sign(payload_bytes, x1, "AS1")
    # Sign again with AS1 key, but CLAIM to be AS2
    R2, s2 = schnorr_sign(payload_bytes, x1, "AS2")

    forged_sigs = [
        {"R": hex(R1), "s": hex(s1), "authority_id": "AS1",
         "public_key": hex(public_keys["AS1"])},
        # AS2 public key does NOT match AS1 private key → will fail
        {"R": hex(R2), "s": hex(s2), "authority_id": "AS2",
         "public_key": hex(public_keys["AS2"])},
    ]

    print("Adversary: signs TGT payload with AS1's private key, claims both AS1 and AS2 identities.")
    print(f"Submitted sigs: {[s['authority_id'] for s in forged_sigs]}")

    # Verify locally so we can show what each node would see
    for sig in forged_sigs:
        R   = int(sig["R"], 16)
        s_v = int(sig["s"], 16)
        pk  = int(sig["public_key"], 16)
        aid = sig["authority_id"]
        ok  = schnorr_verify(payload_bytes, R, s_v, pk, aid)
        print(f"  Local verify {aid}: {'valid' if ok else 'INVALID'}")

    # Build a fake "session key enc" entry (TGS needs the field to be present)
    dummy_key     = sha256(b"dummy_session_key_attack1")
    iv_d, ct_d    = aes256_cbc_encrypt(dummy_key, generate_session_key())
    fake_enc      = {"iv": iv_d.hex(), "ciphertext": ct_d.hex()}

    forged_tgt = {
        "payload":             payload,
        "signatures":          forged_sigs,
        "tgt_session_key_enc": fake_enc,
    }

    # Submit to the real TGS
    print("\nSubmitting forged TGT to live TGS1 ...")
    tgs_resp = _submit_tgt_to_tgs(forged_tgt, client_id="ishaan",
                                   service_id="file_service", tgs_id="TGS1")

    tgs_accepted = tgs_resp.get("status") == "OK"
    print(f"TGS1 response: {tgs_resp.get('status')} — {tgs_resp.get('message', 'OK')}")

    defended = not tgs_accepted
    print_result(
        defended,
        "The forged AS2 signature was produced with AS1's private key but checked "
        "against AS2's (different) public key — Schnorr verification fails. "
        "Only 1 valid unique signature passes; the 2-of-3 threshold is not met. "
        "The live TGS correctly rejects the forged TGT."
    )
    return defended


# ─────────────────────────────────────────────────────────────────────────────
# Attack 2 — Modified Ticket Payload (Tampering Attack)
# ─────────────────────────────────────────────────────────────────────────────

def attack2_modified_ticket_payload() -> bool:
    """
    Scenario
    --------
    An adversary intercepts a legitimately issued TGT for "ishaan" and changes
    the client_id field to "admin" (or any other user) before presenting it to
    the TGS.

    Expected outcome
    ----------------
    DEFENDED — the AS signatures were computed over the original payload bytes.
    Changing client_id changes the SHA-256 hash, invalidating both signatures.
    The live TGS rejects the tampered TGT.
    """
    print_header(2, "Modified Ticket Payload (Tampering Attack)")

    print("Step 1: Obtain a legitimate TGT for 'ishaan' from the live AS cluster ...")
    tgt = _get_real_tgt(client_id="ishaan")
    n   = tgt["_valid_sig_count"]
    print(f"  TGT obtained with {n} valid AS signatures.")

    if n < 2:
        print("  [SKIP] Could not obtain a valid TGT — AS cluster unavailable.")
        return False

    # Tamper: swap client_id
    original_payload = tgt["payload"]
    tampered_payload  = dict(original_payload)
    tampered_payload["client_id"] = "admin"

    print("Step 2: Adversary modifies client_id: 'ishaan' → 'admin' (no re-signing).")

    # Build the tampered TGT keeping the original (now invalid) signatures
    tampered_tgt = {
        "payload":             tampered_payload,
        "signatures":          tgt["signatures"],
        "tgt_session_key_enc": tgt["tgt_session_key_enc"],
    }

    print("Step 3: Submitting tampered TGT to live TGS1 ...")
    tgs_resp    = _submit_tgt_to_tgs(tampered_tgt, client_id="admin",
                                      service_id="file_service", tgs_id="TGS1")
    tgs_accepted = tgs_resp.get("status") == "OK"
    print(f"TGS1 response: {tgs_resp.get('status')} — {tgs_resp.get('message', 'OK')}")

    defended = not tgs_accepted
    print_result(
        defended,
        "Altering client_id changes the canonical payload bytes and therefore the "
        "SHA-256 challenge e = H(payload || R || ID).  Both AS signatures now fail "
        "g^s ≢ R·y^e mod p.  The live TGS correctly rejects the tampered ticket."
    )
    return defended


# ─────────────────────────────────────────────────────────────────────────────
# Attack 3 — Replay of an Old Partial Signature
# ─────────────────────────────────────────────────────────────────────────────

def attack3_replay_old_partial_signature() -> bool:
    """
    Scenario
    --------
    An adversary captures an AS1 signature from a ticket issued 2 hours ago.
    They splice that old (R, s) into a fresh TGT request (with a new timestamp)
    alongside a freshly obtained AS2 signature.

    Expected outcome
    ----------------
    DEFENDED — the replayed AS1 signature was created over old payload bytes
    (different timestamp).  When the TGS verifies g^s ≡ R·y^e mod p using the
    NEW payload bytes, the challenge e changes and AS1's signature fails.
    The live TGS rejects the hybrid TGT.
    """
    print_header(3, "Replay of Old Partial Signature")

    params     = load_system_params()
    public_keys = params["public_keys"]

    x1, y1, _ = load_authority_private_key("AS1")
    x2, y2, _ = load_authority_private_key("AS2")

    # ── Step 1: Create the "old" AS1 signature (2 hours ago) ──────────────────
    old_payload = {
        "client_id":   "ishaan",
        "tgs_id":      "TGS",
        "timestamp":   time.time() - 7200,   # 2 hours ago
        "lifetime":    3600,
        "key_version": params["key_version"],
    }
    old_bytes    = encode_ticket_payload(old_payload)
    R_old, s_old = schnorr_sign(old_bytes, x1, "AS1")
    print("Old AS1 signature captured (timestamp = 2 hours ago).")

    # ── Step 2: Fresh TGT request with a NEW timestamp ────────────────────────
    time.sleep(0.02)
    new_payload = {
        "client_id":   "ishaan",
        "tgs_id":      "TGS",
        "timestamp":   time.time(),
        "lifetime":    3600,
        "key_version": params["key_version"],
    }
    new_bytes = encode_ticket_payload(new_payload)

    # Adversary gets a fresh AS2 signature for the new payload
    R2, s2 = schnorr_sign(new_bytes, x2, "AS2")
    print("Fresh AS2 signature obtained for the new payload.")

    # Verify the replayed AS1 sig against the NEW payload (should fail)
    as1_replay_ok = schnorr_verify(new_bytes, R_old, s_old, y1, "AS1")
    print(f"  Replayed AS1 sig valid on new payload: {'YES (BAD!)' if as1_replay_ok else 'NO (GOOD)'}")

    # ── Step 3: Build hybrid TGT and send to live TGS ─────────────────────────
    hybrid_sigs = [
        {"R": hex(R_old), "s": hex(s_old), "authority_id": "AS1",
         "public_key": hex(y1)},
        {"R": hex(R2),    "s": hex(s2),    "authority_id": "AS2",
         "public_key": hex(y2)},
    ]

    dummy_key  = sha256(b"dummy_session_key_attack3")
    iv_d, ct_d = aes256_cbc_encrypt(dummy_key, generate_session_key())

    hybrid_tgt = {
        "payload":             new_payload,
        "signatures":          hybrid_sigs,
        "tgt_session_key_enc": {"iv": iv_d.hex(), "ciphertext": ct_d.hex()},
    }

    print("Submitting hybrid TGT (replayed AS1 + fresh AS2) to live TGS1 ...")
    tgs_resp    = _submit_tgt_to_tgs(hybrid_tgt, client_id="ishaan",
                                      service_id="file_service", tgs_id="TGS1")
    tgs_accepted = tgs_resp.get("status") == "OK"
    print(f"TGS1 response: {tgs_resp.get('status')} — {tgs_resp.get('message', 'OK')}")

    defended = not tgs_accepted
    print_result(
        defended,
        "The replayed AS1 signature was computed over a payload with an old timestamp. "
        "The new TGT has a different timestamp, changing the payload bytes and hence "
        "the Schnorr challenge.  g^s ≢ R·y^e mod p for the replayed sig — the TGS "
        "counts only 1 valid signature and correctly rejects the hybrid TGT."
    )
    return defended


# ─────────────────────────────────────────────────────────────────────────────
# Attack 4 — Leakage of One Authority's Private Signing Key
# ─────────────────────────────────────────────────────────────────────────────

def attack4_key_leakage() -> bool:
    """
    Scenario
    --------
    AS1's private key is leaked to the adversary.  Using x1 the adversary can
    produce a perfectly valid AS1 signature.  For the second signature (AS2)
    they have no key, so they attempt a random (R, s) pair.

    Expected outcome
    ----------------
    DEFENDED — the random AS2 signature fails Schnorr verification with
    overwhelming probability.  The live TGS counts only 1 valid signature
    and rejects the forged TGT.
    """
    print_header(4, "Leakage of One Authority's Private Signing Key")

    params     = load_system_params()
    public_keys = params["public_keys"]

    x1, y1, _ = load_authority_private_key("AS1")   # leaked
    y2         = public_keys["AS2"]

    payload = {
        "client_id":   "ishaan",
        "tgs_id":      "TGS",
        "timestamp":   time.time(),
        "lifetime":    3600,
        "key_version": params["key_version"],
    }
    payload_bytes = encode_ticket_payload(payload)

    # Adversary produces a valid AS1 signature (they have the key)
    R1, s1 = schnorr_sign(payload_bytes, x1, "AS1")
    print(f"AS1 private key leaked: x1 = {hex(x1)[:18]}...")
    print("Adversary forges a valid AS1 signature.")

    # Adversary tries a random (R, s) as AS2
    R_fake = mod_exp(G, secure_random_scalar(), P)
    s_fake = secure_random_scalar()
    print("Adversary attempts a random Schnorr forgery for AS2 ...")

    as1_ok = schnorr_verify(payload_bytes, R1,     s1,     y1, "AS1")
    as2_ok = schnorr_verify(payload_bytes, R_fake, s_fake, y2, "AS2")
    print(f"  AS1 sig (with leaked key):  {'valid ✓' if as1_ok else 'invalid'}")
    print(f"  AS2 sig (random forgery):   {'valid (BAD!)' if as2_ok else 'invalid ✓'}")

    dummy_key  = sha256(b"dummy_session_key_attack4")
    iv_d, ct_d = aes256_cbc_encrypt(dummy_key, generate_session_key())

    forged_tgt = {
        "payload": payload,
        "signatures": [
            {"R": hex(R1),     "s": hex(s1),     "authority_id": "AS1",
             "public_key": hex(y1)},
            {"R": hex(R_fake), "s": hex(s_fake), "authority_id": "AS2",
             "public_key": hex(y2)},
        ],
        "tgt_session_key_enc": {"iv": iv_d.hex(), "ciphertext": ct_d.hex()},
    }

    print("Submitting forged TGT to live TGS1 ...")
    tgs_resp    = _submit_tgt_to_tgs(forged_tgt, client_id="ishaan",
                                      service_id="file_service", tgs_id="TGS1")
    tgs_accepted = tgs_resp.get("status") == "OK"
    print(f"TGS1 response: {tgs_resp.get('status')} — {tgs_resp.get('message', 'OK')}")

    defended = not tgs_accepted
    print_result(
        defended,
        "Even with AS1's private key leaked, the adversary cannot forge a valid AS2 "
        "signature without AS2's private key (requires solving DLP). "
        "Only 1 valid unique signature — below the 2-of-3 threshold. "
        "The live TGS rejects the ticket. "
        "NOTE: If both AS1 AND AS2 were compromised the threshold would break."
    )
    return defended


# ─────────────────────────────────────────────────────────────────────────────
# Attack 5 — Authority Offline Scenario
# ─────────────────────────────────────────────────────────────────────────────

def attack5_authority_offline() -> bool:
    """
    Scenario
    --------
    Sub-scenario A: AS3 is offline.  The client can still collect 2 valid
    signatures (from AS1 + AS2), assemble a TGT, obtain a Service Ticket
    from the TGS cluster, and successfully access the service.

    Sub-scenario B: AS2 AND AS3 are offline.  Only AS1 responds.  The TGT
    has only 1 valid signature.  The TGS correctly refuses it.

    Expected outcomes
    -----------------
    Sub-A: SYSTEM WORKS — 2-of-3 fault tolerance demonstrated end-to-end.
    Sub-B: AUTHENTICATION FAILS gracefully — degradation attack prevented.
    """
    print_header(5, "Authority Offline Scenario")

    # ── Sub-scenario A: AS3 offline ───────────────────────────────────────────
    print("Sub-scenario A: AS3 is offline — only AS1 and AS2 respond.")
    tgt_a = _get_real_tgt(client_id="ishaan", exclude_as=["AS3"])
    n_a   = tgt_a["_valid_sig_count"]
    print(f"  TGT collected {n_a} valid AS signatures (AS1 + AS2).")

    if n_a < 2:
        print("  [SKIP] Sub-A requires at least 2 online AS nodes.")
        sub_a_pass = False
    else:
        # Go all the way to the Service
        svc_ticket = _collect_service_ticket(tgt_a, client_id="ishaan",
                                              service_id="file_service")
        if svc_ticket is None:
            print("  TGS rejected TGT (unexpected).")
            sub_a_pass = False
        else:
            svc_resp     = _submit_service_ticket(svc_ticket, client_id="ishaan",
                                                   service_id="file_service")
            sub_a_pass   = svc_resp.get("status") == "OK"
            print(f"  Service response: {svc_resp.get('status')} — "
                  f"{svc_resp.get('service_data', svc_resp.get('message', ''))}")

    print(f"  Sub-A result: {' System works with 2 signatures' if sub_a_pass else ' Failed'}")

    # ── Sub-scenario B: AS2 + AS3 offline (only AS1 responds) ────────────────
    print("\nSub-scenario B: AS2 and AS3 are both offline — only AS1 responds.")

    x1, y1, _ = load_authority_private_key("AS1")
    params     = load_system_params()

    solo_payload = {
        "client_id":   "ishaan",
        "tgs_id":      "TGS",
        "timestamp":   time.time(),
        "lifetime":    3600,
        "key_version": params["key_version"],
    }
    solo_bytes = encode_ticket_payload(solo_payload)
    R1, s1     = schnorr_sign(solo_bytes, x1, "AS1")

    dummy_key  = sha256(b"dummy_session_key_attack5b")
    iv_d, ct_d = aes256_cbc_encrypt(dummy_key, generate_session_key())

    solo_tgt = {
        "payload":   solo_payload,
        "signatures": [
            {"R": hex(R1), "s": hex(s1), "authority_id": "AS1",
             "public_key": hex(y1)},
        ],
        "tgt_session_key_enc": {"iv": iv_d.hex(), "ciphertext": ct_d.hex()},
    }

    print("  Submitting 1-signature TGT to live TGS1 ...")
    tgs_resp    = _submit_tgt_to_tgs(solo_tgt, client_id="ishaan",
                                      service_id="file_service", tgs_id="TGS1")
    tgs_accepted = tgs_resp.get("status") == "OK"
    print(f"  TGS1 response: {tgs_resp.get('status')} — {tgs_resp.get('message', 'OK')}")
    sub_b_pass  = not tgs_accepted   # system should REJECT this
    print(f"  Sub-B result: {' TGS correctly refuses 1-sig TGT' if sub_b_pass else ' TGS accepted (BAD!)'}")

    defended = sub_a_pass and sub_b_pass
    print_result(
        defended,
        "Sub-A: 2-of-3 fault tolerance works — the system authenticates successfully "
        "even with one AS offline. "
        "Sub-B: When only one AS is online the TGS correctly refuses authentication, "
        "preventing a degradation attack from being exploited."
    )
    return defended


# ─────────────────────────────────────────────────────────────────────────────
# Attack 6 — Ticket Containing Only One Valid Signature
# ─────────────────────────────────────────────────────────────────────────────

def attack6_single_signature_ticket() -> bool:
    """
    Scenario
    --------
    An attacker (or a single compromised AS) presents a TGT that contains one
    legitimate Schnorr signature (from AS1) and one garbage entry claiming to
    be AS2.

    Expected outcome
    ----------------
    DEFENDED — the garbage AS2 entry fails Schnorr verification.  The live TGS
    counts only 1 valid signature, which is below the 2-of-3 threshold.

    Additionally, even if the TGS were bypassed, the Service server independently
    verifies the Service Ticket — so a forged service ticket would also be
    rejected at Phase 3.
    """
    print_header(6, "Ticket Containing Only One Valid Signature")

    params     = load_system_params()
    public_keys = params["public_keys"]

    x1, y1, _ = load_authority_private_key("AS1")
    y2         = public_keys["AS2"]

    payload = {
        "client_id":   "ishaan",
        "tgs_id":      "TGS",
        "timestamp":   time.time(),
        "lifetime":    3600,
        "key_version": params["key_version"],
    }
    payload_bytes = encode_ticket_payload(payload)

    # Only AS1 signs legitimately
    R1, s1 = schnorr_sign(payload_bytes, x1, "AS1")

    print("Attacker presents TGT with one valid AS1 signature and one garbage AS2 entry.")

    garbage_R = 12345
    garbage_s = 67890

    as1_ok = schnorr_verify(payload_bytes, R1,        s1,        y1, "AS1")
    as2_ok = schnorr_verify(payload_bytes, garbage_R, garbage_s, y2, "AS2")
    print(f"  AS1 signature local check: {'valid ✓' if as1_ok else 'invalid'}")
    print(f"  AS2 garbage  local check:  {'valid (BAD!)' if as2_ok else 'invalid ✓'}")

    dummy_key  = sha256(b"dummy_session_key_attack6")
    iv_d, ct_d = aes256_cbc_encrypt(dummy_key, generate_session_key())

    one_sig_tgt = {
        "payload": payload,
        "signatures": [
            {"R": hex(R1),        "s": hex(s1),        "authority_id": "AS1",
             "public_key": hex(y1)},
            {"R": hex(garbage_R), "s": hex(garbage_s), "authority_id": "AS2",
             "public_key": hex(y2)},
        ],
        "tgt_session_key_enc": {"iv": iv_d.hex(), "ciphertext": ct_d.hex()},
    }

    # ── Phase 2: Submit to the live TGS ───────────────────────────────────────
    print("Submitting 1-valid-sig TGT to live TGS1 ...")
    tgs_resp     = _submit_tgt_to_tgs(one_sig_tgt, client_id="ishaan",
                                       service_id="file_service", tgs_id="TGS1")
    tgs_accepted = tgs_resp.get("status") == "OK"
    print(f"TGS1 response: {tgs_resp.get('status')} — {tgs_resp.get('message', 'OK')}")

    # ── Phase 3: Even if TGS were bypassed, forge a service ticket and try it ─
    print("\nBonus — Service Server defence:")
    print("  Even if TGS were bypassed, a forged 1-sig service ticket would also fail ...")
    forged_st_payload = {
        "client_id":   "ishaan",
        "service_id":  "file_service",
        "timestamp":   time.time(),
        "lifetime":    3600,
        "key_version": params["key_version"],
    }
    xt1, yt1, _ = load_authority_private_key("TGS1")
    fst_bytes    = encode_ticket_payload(forged_st_payload)
    Rt1, st1     = schnorr_sign(fst_bytes, xt1, "TGS1")

    svc_key     = sha256(b"SERVICE" + fst_bytes)
    iv_s, ct_s  = aes256_cbc_encrypt(svc_key, generate_session_key())

    forged_st = {
        "payload": forged_st_payload,
        "signatures": [
            {"R": hex(Rt1),       "s": hex(st1),       "authority_id": "TGS1",
             "public_key": hex(yt1)},
            {"R": hex(garbage_R), "s": hex(garbage_s), "authority_id": "TGS2",
             "public_key": hex(params["public_keys"]["TGS2"])},
        ],
        "iv":         iv_s.hex(),
        "ciphertext": ct_s.hex(),
    }

    svc_resp     = _submit_service_ticket(forged_st, client_id="ishaan",
                                           service_id="file_service")
    svc_accepted = svc_resp.get("status") == "OK"
    print(f"  Service response: {svc_resp.get('status')} — {svc_resp.get('message', 'OK')}")

    defended = (not tgs_accepted) and (not svc_accepted)
    print_result(
        defended,
        "The garbage AS2 entry fails Schnorr verification at the live TGS — only 1 "
        "valid signature is counted, which is below the 2-of-3 threshold. "
        "Additionally, the Service Server independently rejects a 1-valid-TGS-sig "
        "service ticket, providing defence-in-depth."
    )
    return defended


# ─────────────────────────────────────────────────────────────────────────────
# Main runner
# ─────────────────────────────────────────────────────────────────────────────

SCENARIOS = {
    1: attack1_single_malicious_authority,
    2: attack2_modified_ticket_payload,
    3: attack3_replay_old_partial_signature,
    4: attack4_key_leakage,
    5: attack5_authority_offline,
    6: attack6_single_signature_ticket,
}

SCENARIO_NAMES = {
    1: "Single malicious authority issuing forged ticket",
    2: "Modified ticket payload (tampering)",
    3: "Replay of old partial signature",
    4: "Leakage of one authority's private signing key",
    5: "Authority offline scenario",
    6: "Ticket containing only one valid signature",
}


def run_all() -> None:
    print("\n" + "=" * 65)
    print("  Kerberos Multi-Sig — Mandatory Attack Scenario Demonstrations")
    print("=" * 65)

    results = {}
    for num, fn in SCENARIOS.items():
        try:
            results[num] = fn()
        except Exception as exc:
            print(f"\n[ERROR] Scenario {num} raised an exception: {exc}")
            import traceback
            traceback.print_exc()
            results[num] = False

    print("\n" + "=" * 65)
    print("  SUMMARY")
    print("=" * 65)
    all_pass = True
    for num, defended in results.items():
        status = " DEFENDED" if defended else " NOT DEFENDED"
        print(f"  Attack {num}: {SCENARIO_NAMES[num]}")
        print(f"           {status}")
        if not defended:
            all_pass = False

    print()
    if all_pass:
        print("  All attack scenarios successfully defended! ")
    else:
        print("  WARNING: Some scenarios were not defended as expected.")
    print("=" * 65)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run Kerberos Multi-Sig attack scenarios against live servers"
    )
    parser.add_argument(
        "--scenario", type=int, choices=range(1, 7), default=None,
        help="Run a specific attack scenario (1-6). Default: run all."
    )
    parser.add_argument(
        "--no-servers", action="store_true",
        help="Skip starting embedded servers (use if servers are already running)."
    )
    args = parser.parse_args()

    # ── Key bootstrap ──────────────────────────────────────────────────────────
    try:
        _params = load_system_params()
    except FileNotFoundError:
        print("[setup] Keys not found — running master_keygen.py ...")
        import master_keygen
        _k = master_keygen.generate_all_keys(force=False)
        master_keygen.write_system_params(_k)
        _params = load_system_params()

    # ── Server startup ─────────────────────────────────────────────────────────
    if args.no_servers:
        print("[setup] Skipping server startup (--no-servers flag set).")
    elif _servers_already_up(_params):
        print("[setup] Servers appear to be already running — skipping startup.")
    else:
        _start_servers()

    # ── Run scenarios ──────────────────────────────────────────────────────────
    if args.scenario:
        fn = SCENARIOS[args.scenario]
        fn()
    else:
        run_all()
