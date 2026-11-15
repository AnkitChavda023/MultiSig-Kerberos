"""
master_keygen.py
================
Generates and persists Schnorr key pairs for all six authorities:
    AS1, AS2, AS3  (Authentication Server nodes)
    TGS1, TGS2, TGS3  (Ticket Granting Server nodes)

Also writes keys/system_params.json with the public system parameters
(P, Q, G) and ALL public keys so that clients and service servers can
load them without running key generation again.

Output directory: keys/
    keys/AS1.json  ...  keys/AS3.json
    keys/TGS1.json ...  keys/TGS3.json
    keys/system_params.json

JSON format per authority:
{
  "authority_id": "AS1",
  "private_key":  "<hex>",
  "public_key":   "<hex>",
  "key_version":  1
}

system_params.json:
{
  "P": "<hex>",
  "Q": "<hex>",
  "G": "<hex>",
  "public_keys": {
      "AS1":  "<hex>", ...
  },
  "key_version": 1,
  "ports": {
      "AS1": 9001, "AS2": 9002, "AS3": 9003,
      "TGS1": 9101, "TGS2": 9102, "TGS3": 9103,
      "SERVICE": 9200
  }
}
"""

import json
import os
import sys

# Allow running from within the A3 directory
sys.path.insert(0, os.path.dirname(__file__))

from crypto_utils import schnorr_keygen, P, Q, G

KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")

AUTHORITY_IDS = ["AS1", "AS2", "AS3", "TGS1", "TGS2", "TGS3"]

PORTS = {
    "AS1":  9001,
    "AS2":  9002,
    "AS3":  9003,
    "TGS1": 9101,
    "TGS2": 9102,
    "TGS3": 9103,
    "SERVICE": 9200,
}

KEY_VERSION = 1


def generate_all_keys(force: bool = False) -> dict:
    """
    Generate Schnorr key pairs for every authority and save them under keys/.

    If *force* is False and key files already exist, skip regeneration and
    just reload the existing keys.

    Returns a dict mapping authority_id -> {"private_key": int, "public_key": int}.
    """
    os.makedirs(KEYS_DIR, exist_ok=True)

    keys: dict = {}

    for aid in AUTHORITY_IDS:
        key_path = os.path.join(KEYS_DIR, f"{aid}.json")
        if not force and os.path.exists(key_path):
            with open(key_path) as f:
                data = json.load(f)
            x = int(data["private_key"], 16)
            y = int(data["public_key"], 16)
            print(f"[keygen] Loaded existing key for {aid}")
        else:
            x, y = schnorr_keygen()
            data = {
                "authority_id": aid,
                "private_key":  hex(x),
                "public_key":   hex(y),
                "key_version":  KEY_VERSION,
            }
            with open(key_path, "w") as f:
                json.dump(data, f, indent=2)
            print(f"[keygen] Generated new key for {aid} -> {key_path}")

        keys[aid] = {"private_key": x, "public_key": y}

    return keys


def write_system_params(keys: dict) -> None:
    """Write system_params.json with public parameters and all public keys."""
    public_keys = {aid: hex(kd["public_key"]) for aid, kd in keys.items()}
    params = {
        "P":           hex(P),
        "Q":           hex(Q),
        "G":           hex(G),
        "public_keys": public_keys,
        "key_version": KEY_VERSION,
        "ports":       PORTS,
    }
    params_path = os.path.join(KEYS_DIR, "system_params.json")
    with open(params_path, "w") as f:
        json.dump(params, f, indent=2)
    print(f"[keygen] System params written -> {params_path}")


def load_system_params() -> dict:
    """Load and return system_params.json as a dict."""
    params_path = os.path.join(KEYS_DIR, "system_params.json")
    if not os.path.exists(params_path):
        raise FileNotFoundError(
            f"system_params.json not found. Run master_keygen.py first."
        )
    with open(params_path) as f:
        raw = json.load(f)
    # Convert hex strings to ints for convenience
    params = {
        "P":           int(raw["P"], 16),
        "Q":           int(raw["Q"], 16),
        "G":           int(raw["G"], 16),
        "public_keys": {aid: int(pk, 16) for aid, pk in raw["public_keys"].items()},
        "key_version": raw["key_version"],
        "ports":       raw["ports"],
    }
    return params


def load_authority_private_key(authority_id: str) -> tuple:
    """
    Load the private key for a single authority.
    Returns (x: int, y: int, key_version: int).
    """
    key_path = os.path.join(KEYS_DIR, f"{authority_id}.json")
    if not os.path.exists(key_path):
        raise FileNotFoundError(
            f"Key file for {authority_id} not found. Run master_keygen.py first."
        )
    with open(key_path) as f:
        data = json.load(f)
    x = int(data["private_key"], 16)
    y = int(data["public_key"], 16)
    kv = data.get("key_version", 1)
    return x, y, kv


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate Schnorr key pairs for all authorities.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Regenerate keys even if they already exist (invalidates all existing tickets).",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  Kerberos Multi-Sig — Master Key Generation")
    print("=" * 60)

    keys = generate_all_keys(force=args.force)
    write_system_params(keys)

    print("\nPublic key summary:")
    params = load_system_params()
    for aid, pk in params["public_keys"].items():
        print(f"  {aid:6s}  y = {hex(pk)[:18]}...")

    print("\nPort assignments:")
    for name, port in params["ports"].items():
        print(f"  {name:8s}  -> :{port}")

    print("\nKey generation complete.")
