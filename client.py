"""
client.py
=========
Kerberos Multi-Sig Client

Implements the full three-phase authentication protocol:

  Phase 1 — Distributed AS Exchange (TGT acquisition)
    ├── Contact all three AS nodes concurrently.
    ├── Collect valid Schnorr signatures from at least 2.
    └── Assemble multi-signature TGT.

  Phase 2 — Distributed TGS Exchange (Service Ticket acquisition)
    ├── Contact all three TGS nodes concurrently with the TGT.
    ├── Collect valid Schnorr signatures from at least 2.
    └── Assemble multi-signature Service Ticket.

  Phase 3 — Service Authentication
    └── Present Service Ticket to the Service Server and obtain access.

Usage:
    python client.py --client ishaan --service file_service [--password password_ishaan]

Options:
    --client      Client username (default: ishaan)
    --service     Service to access (default: file_service)
    --password    Client password (default: derived from username for demo)
    --host        Server hostname (default: 127.0.0.1)
    --verbose     Print detailed cryptographic information
"""

import argparse
import json
import os
import socket
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(__file__))

from crypto_utils import (
    schnorr_verify,
    verify_multisig,
    aes256_cbc_decrypt,
    sha256,
    encode_ticket_payload,
    generate_session_key,
    aes256_cbc_encrypt,
)
from master_keygen import load_system_params

# Default demo passwords — must match as_node.py USER_REGISTRY
DEFAULT_PASSWORDS = {
    "ishaan":   "password_ishaan",
    # "ishaan":     "password_ishaan",
    "ankit": "password_ankit",
    "vipin":     "password_vipin",
}


# ---------------------------------------------------------------------------
# Low-level TCP helper
# ---------------------------------------------------------------------------

def tcp_send_recv(host: str, port: int, payload: dict, timeout: float = 10.0) -> dict:
    """Send a JSON request and receive a JSON response (newline-delimited)."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(json.dumps(payload).encode() + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    return json.loads(data.decode().strip())


# ---------------------------------------------------------------------------
# Helper: derive client AES key from password
# ---------------------------------------------------------------------------

def derive_client_key(client_id: str, password: str) -> bytes:
    raw = (password + ":" + client_id).encode("utf-8")
    return sha256(raw)


# ---------------------------------------------------------------------------
# Phase 1 — Distributed AS Exchange
# ---------------------------------------------------------------------------

def phase1_get_tgt(
    host: str,
    client_id: str,
    password: str,
    params: dict,
    verbose: bool = False,
) -> dict:
    """
    Contact all three AS nodes, collect ≥2 valid Schnorr signatures,
    assemble and return the multi-signature TGT.
    """
    as_nodes = {
        "AS1": params["ports"]["AS1"],
        "AS2": params["ports"]["AS2"],
        "AS3": params["ports"]["AS3"],
    }

    request = {
        "type":      "AUTH_REQUEST",
        "client_id": client_id,
        "tgs_id":    "TGS",
        "timestamp": time.time(),
    }

    responses = {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {
            pool.submit(tcp_send_recv, host, port, request): aid
            for aid, port in as_nodes.items()
        }
        for future in as_completed(futures):
            aid = futures[future]
            try:
                resp = future.result()
                responses[aid] = resp
                if verbose:
                    print(f"  [Phase1] {aid} responded: {resp.get('status')}")
            except Exception as e:
                print(f"  [Phase1] {aid} UNREACHABLE: {e}")

    # Filter valid responses and verify each Schnorr signature
    client_key = derive_client_key(client_id, password)
    valid_sigs = []
    session_keys = {}    # aid -> decrypted session key
    ticket_payload = None

    for aid, resp in responses.items():
        if resp.get("status") != "OK":
            print(f"  [Phase1] {aid} returned error: {resp.get('message')}")
            continue

        tp = resp["ticket_payload"]
        sig_raw = resp["signature"]
        pk = int(resp["public_key"], 16)
        R = int(sig_raw["R"], 16)
        s = int(sig_raw["s"], 16)

        # Verify this authority's Schnorr signature
        payload_bytes = encode_ticket_payload(tp)
        ok = schnorr_verify(payload_bytes, R, s, pk, aid)
        if not ok:
            print(f"  [Phase1] {aid} Schnorr signature INVALID — discarding")
            continue

        if verbose:
            print(f"  [Phase1] {aid} signature verified ✓")

        # Decrypt the session key the AS encrypted for us
        sk_enc = resp["session_key_encrypted"]
        iv     = bytes.fromhex(sk_enc["iv"])
        ct     = bytes.fromhex(sk_enc["ciphertext"])
        try:
            session_key = aes256_cbc_decrypt(client_key, iv, ct)
            session_keys[aid] = session_key
        except Exception as e:
            print(f"  [Phase1] {aid} session key decryption failed: {e}")
            continue

        valid_sigs.append({
            "R":            hex(R),
            "s":            hex(s),
            "authority_id": aid,
            "public_key":   hex(pk),
        })
        ticket_payload = tp   # All nodes sign the same payload fields

    if len(valid_sigs) < 2:
        raise RuntimeError(
            f"Phase1 FAILED: only {len(valid_sigs)} valid AS signature(s) collected (need ≥2)"
        )

    # Use the session key from any one valid AS (they all generate different
    # session keys; we pick the first valid one consistently).
    chosen_aid = valid_sigs[0]["authority_id"]
    tgs_session_key = session_keys[chosen_aid]
    tgt_enc_ref = responses[chosen_aid]["session_key_encrypted"]

    tgt = {
        "payload":           ticket_payload,
        "signatures":        valid_sigs[:3],   # include up to all 3
        "tgt_session_key_enc": tgt_enc_ref,    # used by TGS for key derivation
    }

    print(f"  [Phase1] TGT assembled with {len(valid_sigs)} valid AS signatures ✓")
    return tgt, tgs_session_key


# ---------------------------------------------------------------------------
# Phase 2 — Distributed TGS Exchange
# ---------------------------------------------------------------------------

def phase2_get_service_ticket(
    host: str,
    client_id: str,
    service_id: str,
    tgt: dict,
    params: dict,
    verbose: bool = False,
) -> dict:
    """
    Contact all three TGS nodes, collect ≥2 valid Schnorr signatures,
    assemble and return the multi-signature Service Ticket.
    """
    tgs_nodes = {
        "TGS1": params["ports"]["TGS1"],
        "TGS2": params["ports"]["TGS2"],
        "TGS3": params["ports"]["TGS3"],
    }

    request = {
        "type":       "TGS_REQUEST",
        "client_id":  client_id,
        "service_id": service_id,
        "timestamp":  time.time(),
        "tgt":        tgt,
    }

    responses = {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {
            pool.submit(tcp_send_recv, host, port, request): aid
            for aid, port in tgs_nodes.items()
        }
        for future in as_completed(futures):
            aid = futures[future]
            try:
                resp = future.result()
                responses[aid] = resp
                if verbose:
                    print(f"  [Phase2] {aid} responded: {resp.get('status')}")
            except Exception as e:
                print(f"  [Phase2] {aid} UNREACHABLE: {e}")

    # Filter valid responses and verify each TGS Schnorr signature
    valid_sigs = []
    service_ticket_payload = None
    service_session_key = None

    for aid, resp in responses.items():
        if resp.get("status") != "OK":
            print(f"  [Phase2] {aid} returned error: {resp.get('message')}")
            continue

        tp  = resp["ticket_payload"]
        sig_raw = resp["signature"]
        pk  = int(resp["public_key"], 16)
        R   = int(sig_raw["R"], 16)
        s   = int(sig_raw["s"], 16)

        payload_bytes = encode_ticket_payload(tp)
        ok = schnorr_verify(payload_bytes, R, s, pk, aid)
        if not ok:
            print(f"  [Phase2] {aid} Schnorr signature INVALID — discarding")
            continue

        if verbose:
            print(f"  [Phase2] {aid} signature verified ✓")

        # Decrypt service session key
        ssk_enc = resp["enc_service_session_key"]
        tgt_enc_bytes = (
            bytes.fromhex(tgt["tgt_session_key_enc"]["iv"]) +
            bytes.fromhex(tgt["tgt_session_key_enc"]["ciphertext"])
        )
        tgs_key = sha256(tgt_enc_bytes)
        iv  = bytes.fromhex(ssk_enc["iv"])
        ct  = bytes.fromhex(ssk_enc["ciphertext"])
        try:
            ssk = aes256_cbc_decrypt(tgs_key, iv, ct)
            if service_session_key is None:
                service_session_key = ssk
        except Exception as e:
            print(f"  [Phase2] {aid} service session key decryption failed: {e}")
            continue

        valid_sigs.append({
            "R":            hex(R),
            "s":            hex(s),
            "authority_id": aid,
            "public_key":   hex(pk),
        })
        service_ticket_payload = tp

    if len(valid_sigs) < 2:
        raise RuntimeError(
            f"Phase2 FAILED: only {len(valid_sigs)} valid TGS signature(s) collected (need ≥2)"
        )

    # Build the AES-encrypted blob for the service server to verify
    svc_payload_bytes = encode_ticket_payload(service_ticket_payload)
    svc_key = sha256(b"SERVICE" + svc_payload_bytes)
    iv_svc, ct_svc = aes256_cbc_encrypt(svc_key, service_session_key or b"\x00" * 32)

    service_ticket = {
        "payload":    service_ticket_payload,
        "signatures": valid_sigs,
        "iv":         iv_svc.hex(),
        "ciphertext": ct_svc.hex(),
    }

    print(f"  [Phase2] Service Ticket assembled with {len(valid_sigs)} valid TGS signatures ✓")
    return service_ticket, service_session_key


# ---------------------------------------------------------------------------
# Phase 3 — Service Authentication
# ---------------------------------------------------------------------------

def phase3_access_service(
    host: str,
    client_id: str,
    service_id: str,
    service_ticket: dict,
    params: dict,
    verbose: bool = False,
) -> str:
    """
    Present the Service Ticket to the Service Server.
    Returns the service response data on success.
    """
    port = params["ports"]["SERVICE"]

    request = {
        "type":           "SERVICE_REQUEST",
        "client_id":      client_id,
        "service_id":     service_id,
        "timestamp":      time.time(),
        "service_ticket": service_ticket,
    }

    resp = tcp_send_recv(host, port, request)

    if resp.get("status") != "OK":
        raise RuntimeError(f"Service access DENIED: {resp.get('message')}")

    print(f"  [Phase3] Service access GRANTED ✓")
    return resp.get("service_data", "")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_client(
    client_id: str,
    password: str,
    service_id: str,
    host: str = "127.0.0.1",
    verbose: bool = False,
) -> None:
    params = load_system_params()

    print("=" * 60)
    print(f"  Kerberos Multi-Sig Client")
    print(f"  Client: {client_id}   Service: {service_id}")
    print("=" * 60)

    # Phase 1
    print("\n[Phase 1] Requesting TGT from AS cluster ...")
    t0 = time.time()
    tgt, tgs_session_key = phase1_get_tgt(host, client_id, password, params, verbose)
    t1 = time.time()
    print(f"  Phase 1 completed in {(t1-t0)*1000:.1f} ms")

    # Phase 2
    print("\n[Phase 2] Requesting Service Ticket from TGS cluster ...")
    t2 = time.time()
    service_ticket, service_session_key = phase2_get_service_ticket(
        host, client_id, service_id, tgt, params, verbose
    )
    t3 = time.time()
    print(f"  Phase 2 completed in {(t3-t2)*1000:.1f} ms")

    # Phase 3
    print("\n[Phase 3] Presenting Service Ticket to Service Server ...")
    t4 = time.time()
    service_data = phase3_access_service(
        host, client_id, service_id, service_ticket, params, verbose
    )
    t5 = time.time()
    print(f"  Phase 3 completed in {(t5-t4)*1000:.1f} ms")

    print("\n" + "=" * 60)
    print("  SERVICE RESPONSE:")
    print(f"  {service_data}")
    print("=" * 60)
    print(f"\nTotal authentication time: {(t5-t0)*1000:.1f} ms")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Kerberos Multi-Sig Client"
    )
    parser.add_argument("--client",   default="ishaan",        help="Client username")
    parser.add_argument("--service",  default="file_service", help="Service to access")
    parser.add_argument("--password", default=None,           help="Client password")
    parser.add_argument("--host",     default="127.0.0.1",    help="Server hostname")
    parser.add_argument("--verbose",  action="store_true",    help="Verbose crypto output")
    args = parser.parse_args()

    password = args.password or DEFAULT_PASSWORDS.get(args.client, "password_" + args.client)

    run_client(args.client, password, args.service, args.host, args.verbose)
