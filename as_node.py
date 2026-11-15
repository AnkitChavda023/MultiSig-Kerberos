"""
as_node.py
==========
Authentication Server (AS) authority node.

Each of the three AS instances (AS1, AS2, AS3) runs as an independent
TCP server process on its own port.  When a client requests a TGT
(Ticket-Granting Ticket), this node:

  1. Verifies the client ID is known (simple user registry).
  2. Generates a fresh session key for the client <-> TGS channel.
  3. Constructs the TGT payload (client_id, tgs_id, timestamp, lifetime,
     session_key, key_version).
  4. Signs the canonical payload with its own Schnorr private key.
  5. AES-encrypts the session key with a per-client "password-derived" key
     so only the legitimate client can decrypt it.
  6. Returns a JSON response containing:
       - The Schnorr signature (R, s, authority_id, public_key)
       - The AES-encrypted session key (iv + ciphertext, hex)
       - Ticket payload fields (plaintext, for aggregation by the client)

The client must collect responses from at least 2 of the 3 AS nodes,
then assemble the multi-signature TGT.

Usage:
    python as_node.py AS1
    python as_node.py AS2
    python as_node.py AS3

Protocol (JSON over TCP, newline-delimited):
    Request:
        { "type": "AUTH_REQUEST",
          "client_id": "<str>",
          "tgs_id": "TGS",
          "timestamp": <unix_float> }

    Response (success):
        { "status": "OK",
          "authority_id": "AS1",
          "ticket_payload": { ... },
          "signature": { "R": "<hex>", "s": "<hex>" },
          "enc_session_key": { "iv": "<hex>", "ciphertext": "<hex>" },
          "public_key": "<hex>",
          "key_version": 1 }

    Response (error):
        { "status": "ERROR", "message": "<reason>" }
"""

import json
import os
import socket
import sys
import time
import threading
import hashlib

sys.path.insert(0, os.path.dirname(__file__))

from crypto_utils import (
    schnorr_sign,
    generate_session_key,
    aes256_cbc_encrypt,
    sha256,
    encode_ticket_payload,
)
from master_keygen import load_authority_private_key, load_system_params

# ---------------------------------------------------------------------------
# Simple in-memory user registry
# In a real system this would be a database with proper password storage.
# Password-derived key: SHA-256(password || client_id)
# ---------------------------------------------------------------------------
USER_REGISTRY = {
    # "alice":   "password_alice",
    "ishaan":     "password_ishaan",
    "ankit": "password_ankit",
    "vipin":     "password_vipin",        # attacker account (valid user)
}

TICKET_LIFETIME = 3600  # seconds (1 hour)


def derive_client_key(client_id: str, password: str) -> bytes:
    """Derive a 32-byte AES key from client credentials."""
    raw = (password + ":" + client_id).encode("utf-8")
    return sha256(raw)


def handle_client(conn: socket.socket, addr, authority_id: str, x: int, y: int, key_version: int) -> None:
    """Handle a single client connection."""
    try:
        data = b""
        while not data.endswith(b"\n"):
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk

        request = json.loads(data.decode("utf-8").strip())

        if request.get("type") != "AUTH_REQUEST":
            resp = {"status": "ERROR", "message": "Unknown request type"}
            conn.sendall(json.dumps(resp).encode() + b"\n")
            return

        client_id = request.get("client_id", "")
        tgs_id    = request.get("tgs_id", "TGS")
        timestamp = request.get("timestamp", time.time())

        # Validate client
        if client_id not in USER_REGISTRY:
            resp = {"status": "ERROR", "message": f"Unknown client: {client_id}"}
            conn.sendall(json.dumps(resp).encode() + b"\n")
            return

        # Generate a fresh session key (client <-> TGS)
        session_key = generate_session_key()

        # Build the ticket payload (canonical, signable)
        ticket_payload = {
            "client_id":   client_id,
            "tgs_id":      tgs_id,
            "timestamp":   timestamp,
            "lifetime":    TICKET_LIFETIME,
            "key_version": key_version,
        }

        # Encode payload for signing
        payload_bytes = encode_ticket_payload(ticket_payload)

        # Sign with this authority's private key
        R, s = schnorr_sign(payload_bytes, x, authority_id)

        # Encrypt session key with client's password-derived key
        client_key = derive_client_key(client_id, USER_REGISTRY[client_id])
        iv, enc_sk = aes256_cbc_encrypt(client_key, session_key)

        response = {
            "status":       "OK",
            "authority_id": authority_id,
            "ticket_payload": ticket_payload,
            "signature": {
                "R": hex(R),
                "s": hex(s),
            },
            "session_key_encrypted": {
                "iv":         iv.hex(),
                "ciphertext": enc_sk.hex(),
            },
            "public_key":  hex(y),
            "key_version": key_version,
        }

        print(f"[{authority_id}] Signed TGT for client '{client_id}' from {addr}")
        conn.sendall(json.dumps(response).encode() + b"\n")

    except Exception as exc:
        print(f"[{authority_id}] Error handling {addr}: {exc}")
        try:
            resp = {"status": "ERROR", "message": str(exc)}
            conn.sendall(json.dumps(resp).encode() + b"\n")
        except Exception:
            pass
    finally:
        conn.close()


def run_as_node(authority_id: str) -> None:
    """Start the AS authority server."""
    params  = load_system_params()
    port    = params["ports"][authority_id]
    x, y, key_version = load_authority_private_key(authority_id)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(20)

    print(f"[{authority_id}] AS node listening on port {port}")
    print(f"[{authority_id}] Public key: {hex(y)[:20]}...")

    while True:
        try:
            conn, addr = server.accept()
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr, authority_id, x, y, key_version),
                daemon=True,
            )
            t.start()
        except KeyboardInterrupt:
            print(f"\n[{authority_id}] Shutting down.")
            break
    server.close()


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("AS1", "AS2", "AS3"):
        print("Usage: python as_node.py <AS1|AS2|AS3>")
        sys.exit(1)
    run_as_node(sys.argv[1])
