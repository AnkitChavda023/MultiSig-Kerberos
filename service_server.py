"""
service_server.py
=================
Service Server — the final protected resource in the Kerberos multi-sig flow.

The service server:
  1. Receives the multi-signature Service Ticket from the client.
  2. Decrypts it with the shared service session key (sent by TGS).
  3. Verifies at least two independent Schnorr signatures from the TGS
     cluster using the publicly known TGS public keys.
  4. Checks the key_version is current.
  5. Checks the ticket has not expired.
  6. On success, grants access to the requested service resource.

Usage:
    python service_server.py

The service server listens on port 9200 (configurable via system_params.json).

Protocol (JSON over TCP, newline-delimited):
    Request:
        { "type": "SERVICE_REQUEST",
          "client_id": "<str>",
          "service_id": "<str>",
          "timestamp": <unix_float>,
          "service_ticket": {
              "payload": { ... },
              "signatures": [
                  { "R": "<hex>", "s": "<hex>",
                    "authority_id": "TGS1", "public_key": "<hex>" },
                  ...
              ],
              "iv": "<hex>",
              "ciphertext": "<hex>"
          }
        }

    Response (success):
        { "status": "OK",
          "message": "Access granted to service '<service_id>'",
          "service_data": "<str>" }

    Response (error):
        { "status": "ERROR", "message": "<reason>" }
"""

import json
import os
import socket
import sys
import time
import threading

sys.path.insert(0, os.path.dirname(__file__))

from crypto_utils import (
    verify_multisig,
    aes256_cbc_decrypt,
    sha256,
    encode_ticket_payload,
)
from master_keygen import load_system_params

# Simulated service catalogue
SERVICE_CATALOGUE = {
    "file_service":  "Welcome to the File Service. Here are your files: [doc1.txt, doc2.pdf]",
    "print_service": "Welcome to the Print Service. Your print job has been queued.",
    "email_service": "Welcome to the Email Service. You have 3 new messages.",
}


def _parse_sig_list(raw_sigs: list, public_keys: dict) -> list:
    parsed = []
    for sig in raw_sigs:
        aid = sig["authority_id"]
        pk  = public_keys.get(aid)
        if pk is None:
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

        if request.get("type") != "SERVICE_REQUEST":
            resp = {"status": "ERROR", "message": "Unknown request type"}
            conn.sendall(json.dumps(resp).encode() + b"\n")
            return

        client_id  = request.get("client_id", "")
        service_id = request.get("service_id", "")
        st         = request.get("service_ticket", {})

        if not st:
            resp = {"status": "ERROR", "message": "Missing Service Ticket"}
            conn.sendall(json.dumps(resp).encode() + b"\n")
            return

        st_payload  = st.get("payload", {})
        raw_sigs    = st.get("signatures", [])
        iv_hex      = st.get("iv", "")
        ct_hex      = st.get("ciphertext", "")

        # ---- Check key version ----
        st_kv = st_payload.get("key_version", 0)
        if st_kv != params["key_version"]:
            print(f"[SERVICE]  ATTACK DETECTED — outdated key version from {addr}: "
                  f"ticket has version {st_kv}, current is {params['key_version']}")
            resp = {"status": "ERROR", "message": f"Outdated key version in Service Ticket: {st_kv}"}
            conn.sendall(json.dumps(resp).encode() + b"\n")
            return

        # ---- Check ticket expiry ----
        issue_time = st_payload.get("timestamp", 0)
        lifetime   = st_payload.get("lifetime", 0)
        if time.time() > issue_time + lifetime:
            print(f"[SERVICE]  REPLAY/EXPIRED TICKET from '{client_id}' at {addr} — "
                  f"issued {issue_time}, lifetime {lifetime}s")
            resp = {"status": "ERROR", "message": "Service Ticket has expired"}
            conn.sendall(json.dumps(resp).encode() + b"\n")
            return

        # ---- Verify at least 2 TGS Schnorr signatures ----
        # Only check TGS authority IDs
        tgs_public_keys = {k: v for k, v in params["public_keys"].items() if k.startswith("TGS")}
        payload_bytes   = encode_ticket_payload(st_payload)
        parsed_sigs     = _parse_sig_list(raw_sigs, tgs_public_keys)

        # Log each signature result
        valid_ids   = []
        invalid_ids = []
        for sig in parsed_sigs:
            aid = sig["authority_id"]
            ok  = verify_multisig(payload_bytes, [sig], threshold=1)
            if ok:
                valid_ids.append(aid)
            else:
                invalid_ids.append(aid)

        if invalid_ids:
            print(f"[SERVICE]   SUSPICIOUS REQUEST from {addr}: "
                  f"INVALID TGS signatures from {invalid_ids} in service ticket for '{client_id}'")

        if not verify_multisig(payload_bytes, parsed_sigs, threshold=2):
            print(f"[SERVICE]  ATTACK DETECTED — SERVICE TICKET REJECTED for '{client_id}' from {addr}: "
                  f"only {len(valid_ids)} valid TGS signature(s) {valid_ids} — threshold 2 not met "
                  f"(invalid: {invalid_ids})")
            resp = {"status": "ERROR", "message": "Service Ticket multi-signature verification FAILED — ticket rejected"}
            conn.sendall(json.dumps(resp).encode() + b"\n")
            return

        # ---- Verify client_id and service_id match ----
        if st_payload.get("client_id") != client_id:
            print(f"[SERVICE]  ATTACK DETECTED — client_id MISMATCH from {addr}: "
                  f"ticket says '{st_payload.get('client_id')}' but request claims '{client_id}'")
            resp = {"status": "ERROR", "message": "client_id mismatch in Service Ticket"}
            conn.sendall(json.dumps(resp).encode() + b"\n")
            return

        if st_payload.get("service_id") != service_id:
            print(f"[SERVICE]  ATTACK DETECTED — service_id MISMATCH from {addr}: "
                  f"ticket says '{st_payload.get('service_id')}' but request claims '{service_id}'")
            resp = {"status": "ERROR", "message": "service_id mismatch in Service Ticket"}
            conn.sendall(json.dumps(resp).encode() + b"\n")
            return

        # ---- Decrypt AES-encrypted portion (if present) ----
        # The service ticket may carry an AES-encrypted session key blob.
        # Verify it is well-formed if present.
        if iv_hex and ct_hex:
            try:
                # Service server derives its own key to validate AES integrity.
                # Key = SHA-256("SERVICE" || payload_bytes)
                svc_key = sha256(b"SERVICE" + payload_bytes)
                _ = aes256_cbc_decrypt(svc_key, bytes.fromhex(iv_hex), bytes.fromhex(ct_hex))
            except Exception as e:
                resp = {"status": "ERROR", "message": f"AES decryption failed: {e}"}
                conn.sendall(json.dumps(resp).encode() + b"\n")
                return

        # ---- Grant access ----
        service_data = SERVICE_CATALOGUE.get(
            service_id,
            f"Welcome to {service_id}. Access granted.",
        )
        response = {
            "status":       "OK",
            "message":      f"Access granted to service '{service_id}'",
            "service_data": service_data,
        }
        print(f"[SERVICE] Access GRANTED to '{client_id}' for service '{service_id}' from {addr}")
        conn.sendall(json.dumps(response).encode() + b"\n")

    except Exception as exc:
        import traceback
        print(f"[SERVICE] Error handling {addr}: {exc}")
        traceback.print_exc()
        try:
            resp = {"status": "ERROR", "message": str(exc)}
            conn.sendall(json.dumps(resp).encode() + b"\n")
        except Exception:
            pass
    finally:
        conn.close()


def run_service_server() -> None:
    params = load_system_params()
    port   = params["ports"]["SERVICE"]

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(20)

    print(f"[SERVICE] Service server listening on port {port}")
    print(f"[SERVICE] Available services: {list(SERVICE_CATALOGUE.keys())}")

    while True:
        try:
            conn, addr = server.accept()
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr, params),
                daemon=True,
            )
            t.start()
        except KeyboardInterrupt:
            print("\n[SERVICE] Shutting down.")
            break
    server.close()


if __name__ == "__main__":
    run_service_server()
