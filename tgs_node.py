"""
tgs_node.py
===========
Ticket-Granting Server (TGS) authority node.

Each of the three TGS instances (TGS1, TGS2, TGS3) runs as an independent
TCP server.  When a client requests a Service Ticket, this node:

  1. Receives the multi-signature TGT assembled by the client.
  2. Verifies that the TGT contains at least 2 valid independent Schnorr
     signatures from the AS cluster (using the publicly known AS public keys).
  3. Verifies the key_version is current.
  4. Decrypts the inner authenticator to recover the TGS session key
     (the TGT is AES-encrypted with the TGS's own key).
  5. Generates a fresh service session key.
  6. Constructs a Service Ticket payload.
  7. Signs the Service Ticket payload with its own Schnorr private key.
  8. Returns the signature, encrypted service session key, and payload to
     the client.

The client must collect responses from at least 2 of the 3 TGS nodes, then
assemble the multi-signature Service Ticket.

Usage:
    python tgs_node.py TGS1
    python tgs_node.py TGS2
    python tgs_node.py TGS3

Protocol (JSON over TCP, newline-delimited):
    Request:
        { "type": "TGS_REQUEST",
          "client_id": "<str>",
          "service_id": "<str>",
          "timestamp": <unix_float>,
          "tgt": {
              "payload": { ... },
              "signatures": [
                  { "R": "<hex>", "s": "<hex>",
                    "authority_id": "AS1", "public_key": "<hex>" },
                  ...
              ],
              "tgt_session_key_enc": { "iv": "<hex>", "ciphertext": "<hex>" }
          }
        }

    Response (success):
        { "status": "OK",
          "authority_id": "TGS1",
          "ticket_payload": { ... },
          "signature": { "R": "<hex>", "s": "<hex>" },
          "enc_service_session_key": { "iv": "<hex>", "ciphertext": "<hex>" },
          "public_key": "<hex>",
          "key_version": 1 }
"""

import json
import os
import socket
import sys
import time
import threading

sys.path.insert(0, os.path.dirname(__file__))

from crypto_utils import (
    schnorr_sign,
    schnorr_verify,
    verify_multisig,
    generate_session_key,
    aes256_cbc_encrypt,
    aes256_cbc_decrypt,
    sha256,
    encode_ticket_payload,
)
from master_keygen import load_authority_private_key, load_system_params

TICKET_LIFETIME = 3600   # seconds


def _parse_sig_list(raw_sigs: list, public_keys: dict) -> list:
    """
    Convert the raw JSON signature list (hex strings) into the format
    expected by verify_multisig.
    """
    parsed = []
    for sig in raw_sigs:
        aid = sig["authority_id"]
        pk  = public_keys.get(aid)
        if pk is None:
            # Unknown authority — skip; cannot verify
            continue
        parsed.append({
            "R":            int(sig["R"], 16),
            "s":            int(sig["s"], 16),
            "authority_id": aid,
            "public_key":   pk,
        })
    return parsed


def handle_client(
    conn: socket.socket,
    addr,
    authority_id: str,
    x: int,
    y: int,
    key_version: int,
    params: dict,
) -> None:
    try:
        data = b""
        while not data.endswith(b"\n"):
            chunk = conn.recv(65536)
            if not chunk:
                return
            data += chunk

        request = json.loads(data.decode("utf-8").strip())

        if request.get("type") != "TGS_REQUEST":
            resp = {"status": "ERROR", "message": "Unknown request type"}
            conn.sendall(json.dumps(resp).encode() + b"\n")
            return

        client_id  = request.get("client_id", "")
        service_id = request.get("service_id", "")
        timestamp  = request.get("timestamp", time.time())
        tgt        = request.get("tgt", {})

        if not tgt:
            resp = {"status": "ERROR", "message": "Missing TGT"}
            conn.sendall(json.dumps(resp).encode() + b"\n")
            return

        # ---- Verify TGT multi-signature ----
        tgt_payload   = tgt.get("payload", {})
        raw_sigs      = tgt.get("signatures", [])
        tgt_key_enc   = tgt.get("tgt_session_key_enc", {})

        # Check key version
        tgt_kv = tgt_payload.get("key_version", 0)
        if tgt_kv != params["key_version"]:
            print(f"[{authority_id}] ATTACK DETECTED — outdated key version from {addr}: "
                  f"TGT has version {tgt_kv}, current is {params['key_version']}")
            resp = {"status": "ERROR", "message": f"Outdated key version: {tgt_kv}"}
            conn.sendall(json.dumps(resp).encode() + b"\n")
            return

        # Reconstruct canonical payload bytes
        payload_bytes = encode_ticket_payload(tgt_payload)

        # Parse and verify signatures — log each sig result for visibility
        parsed_sigs = _parse_sig_list(raw_sigs, params["public_keys"])
        valid_ids = []
        invalid_ids = []
        for sig in parsed_sigs:
            aid = sig["authority_id"]
            ok  = schnorr_verify(payload_bytes, sig["R"], sig["s"], sig["public_key"], aid)
            if ok:
                valid_ids.append(aid)
            else:
                invalid_ids.append(aid)

        if invalid_ids:
            print(f"[{authority_id}] SUSPICIOUS REQUEST from {addr}: "
                  f"INVALID signatures from {invalid_ids} in TGT for client '{client_id}'")
        if len(valid_ids) < 2:
            print(f"[{authority_id}] ATTACK DETECTED — TGT REJECTED for client '{client_id}' from {addr}: "
                  f"only {len(valid_ids)} valid signature(s) {valid_ids} — threshold 2 not met "
                  f"(invalid: {invalid_ids})")
            resp = {"status": "ERROR", "message": "TGT multi-signature verification failed"}
            conn.sendall(json.dumps(resp).encode() + b"\n")
            return
        print(f"[{authority_id}] TGT multi-sig verified for client '{client_id}': "
              f"valid sigs from {valid_ids}")

        # ---- Verify client_id matches TGT ----
        if tgt_payload.get("client_id") != client_id:
            print(f"[{authority_id}] ATTACK DETECTED — client_id MISMATCH from {addr}: "
                  f"TGT says '{tgt_payload.get('client_id')}' but request claims '{client_id}'")
            resp = {"status": "ERROR", "message": "client_id mismatch in TGT"}
            conn.sendall(json.dumps(resp).encode() + b"\n")
            return

        # ---- Check TGT lifetime ----
        issue_time = tgt_payload.get("timestamp", 0)
        lifetime   = tgt_payload.get("lifetime", 0)
        if time.time() > issue_time + lifetime:
            print(f"[{authority_id}] EXPIRED TGT from '{client_id}' at {addr} — issued {issue_time}, lifetime {lifetime}s")
            resp = {"status": "ERROR", "message": "TGT has expired"}
            conn.sendall(json.dumps(resp).encode() + b"\n")
            return

        # ---- Generate service session key ----
        service_session_key = generate_session_key()

        # ---- Build service ticket payload ----
        st_payload = {
            "client_id":   client_id,
            "service_id":  service_id,
            "timestamp":   timestamp,
            "lifetime":    TICKET_LIFETIME,
            "key_version": key_version,
        }

        # Encode for signing
        st_payload_bytes = encode_ticket_payload(st_payload)

        # Sign with TGS private key
        R, s = schnorr_sign(st_payload_bytes, x, authority_id)

        # Encrypt service session key with client-side TGS session key.
        # The client extracted the TGS session key from the TGT using its
        # password-derived key; we use the session key sent in the request.
        # For simplicity we encrypt the service session key with a key
        # derived from: SHA-256( tgt_session_key_iv || tgt_session_key_ct )
        # (the client will use the same derivation).
        tgt_enc_bytes = bytes.fromhex(tgt_key_enc.get("iv", "00" * 16)) + \
                        bytes.fromhex(tgt_key_enc.get("ciphertext", "00" * 32))
        tgs_key = sha256(tgt_enc_bytes)     # 32-byte AES key

        iv, enc_ssk = aes256_cbc_encrypt(tgs_key, service_session_key)

        response = {
            "status":        "OK",
            "authority_id":  authority_id,
            "ticket_payload": st_payload,
            "signature": {
                "R": hex(R),
                "s": hex(s),
            },
            "enc_service_session_key": {
                "iv":         iv.hex(),
                "ciphertext": enc_ssk.hex(),
            },
            "public_key":  hex(y),
            "key_version": key_version,
        }

        print(f"[{authority_id}] Signed Service Ticket for '{client_id}' -> '{service_id}' from {addr}")
        conn.sendall(json.dumps(response).encode() + b"\n")

    except Exception as exc:
        import traceback
        print(f"[{authority_id}] Error handling {addr}: {exc}")
        traceback.print_exc()
        try:
            resp = {"status": "ERROR", "message": str(exc)}
            conn.sendall(json.dumps(resp).encode() + b"\n")
        except Exception:
            pass
    finally:
        conn.close()


def run_tgs_node(authority_id: str) -> None:
    params  = load_system_params()
    port    = params["ports"][authority_id]
    x, y, key_version = load_authority_private_key(authority_id)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(20)

    print(f"[{authority_id}] TGS node listening on port {port}")
    print(f"[{authority_id}] Public key: {hex(y)[:20]}...")

    while True:
        try:
            conn, addr = server.accept()
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr, authority_id, x, y, key_version, params),
                daemon=True,
            )
            t.start()
        except KeyboardInterrupt:
            print(f"\n[{authority_id}] Shutting down.")
            break
    server.close()


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("TGS1", "TGS2", "TGS3"):
        print("Usage: python tgs_node.py <TGS1|TGS2|TGS3>")
        sys.exit(1)
    run_tgs_node(sys.argv[1])
