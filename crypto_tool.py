#!/usr/bin/env python3
"""
File encryption/decryption tool using AES-256-GCM with a password-derived key.

Uses PBKDF2-HMAC-SHA256 for key derivation (600,000 iterations, per current
OWASP guidance) and AES-GCM for authenticated encryption.

Output file format: [16-byte salt][12-byte nonce][ciphertext+16-byte tag]

Usage:
    python3 crypto_tool.py encrypt secret.txt secret.txt.enc
    python3 crypto_tool.py decrypt secret.txt.enc secret.txt.out

Requires: pip install cryptography
"""

import argparse
import getpass
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SALT_LEN = 16
NONCE_LEN = 12
KDF_ITERATIONS = 600_000


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(in_path: str, out_path: str, password: str):
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    with open(in_path, "rb") as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    with open(out_path, "wb") as f:
        f.write(salt + nonce + ciphertext)

    print(f"[+] Encrypted {in_path} -> {out_path} ({len(plaintext)} bytes plaintext)")


def decrypt_file(in_path: str, out_path: str, password: str):
    with open(in_path, "rb") as f:
        data = f.read()

    salt = data[:SALT_LEN]
    nonce = data[SALT_LEN:SALT_LEN + NONCE_LEN]
    ciphertext = data[SALT_LEN + NONCE_LEN:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except Exception:
        print("[!] Decryption failed - wrong password or corrupted/tampered file.")
        sys.exit(1)

    with open(out_path, "wb") as f:
        f.write(plaintext)

    print(f"[+] Decrypted {in_path} -> {out_path} ({len(plaintext)} bytes plaintext)")


def main():
    parser = argparse.ArgumentParser(description="AES-256-GCM file encryption tool")
    parser.add_argument("mode", choices=["encrypt", "decrypt"])
    parser.add_argument("input", help="Input file path")
    parser.add_argument("output", help="Output file path")
    args = parser.parse_args()

    password = getpass.getpass("Password: ")
    if args.mode == "encrypt":
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("[!] Passwords do not match.")
            sys.exit(1)
        encrypt_file(args.input, args.output, password)
    else:
        decrypt_file(args.input, args.output, password)


if __name__ == "__main__":
    main()
