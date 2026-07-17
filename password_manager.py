# password_manager.py
#
# A local, encrypted password manager.
#
# WHAT THIS PROGRAM DOES
# -----------------------
# You pick one "master password." This program never stores that password
# anywhere. Instead, every time you unlock your vault, it re-derives an
# encryption key FROM your master password (using Argon2id) and uses that
# key to decrypt your vault file. If you type the wrong master password,
# the derived key will be wrong, and decryption will fail loudly (it will
# NOT silently return garbage) because we use an "authenticated" cipher.
#
# THE TWO BIG CRYPTO IDEAS USED HERE
# -----------------------------------
# 1. Argon2id (key derivation): Turns a human-memorable password into a
# fixed-length, high-entropy encryption key. It is deliberately SLOW
# and memory-hungry, which makes brute-forcing your master password
# expensive for an attacker, even if they steal your vault file.
#
# 2. AES-256-GCM (authenticated encryption): Encrypts your vault data AND
# produces a "tag" that proves the ciphertext hasn't been tampered
# with. If a single byte of the encrypted file is corrupted or
# modified, decryption fails instead of returning corrupted plaintext.
#
# VAULT FILE FORMAT (on disk)
# -----------------------------
# The vault is a single JSON file containing:
# - kdf_salt : random bytes used by Argon2id (base64 string)
# - nonce : random bytes used by AES-GCM, a.k.a. "IV" (base64)
# - ciphertext : your encrypted credentials (base64)
# The salt and nonce are NOT secret — they're stored in plaintext next to
# the ciphertext on purpose. That's how this scheme is designed to work.
# What must stay secret is only your master password.
from __future__ import annotations
import argparse
import base64
import getpass
import json
import os
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# -----------------------------------------------------------------------
# Tunable constants
# -----------------------------------------------------------------------
DEFAULT_VAULT_PATH = Path.home() / ".password_manager" / "vault.json"
# Argon2id parameters. These control the "cost" of deriving a key.
# Higher = slower to brute-force, but also slower for YOU to unlock.
# These values follow OWASP's current baseline recommendation for
# interactive, single-user applications.
ARGON2_TIME_COST = 3 # number of iterations
ARGON2_MEMORY_COST_KIB = 65536 # 64 MiB of memory
ARGON2_PARALLELISM = 4 # number of parallel threads
ARGON2_HASH_LEN = 32 # 32 bytes = 256-bit key, matches AES-256
SALT_LEN = 16 # 128-bit salt for Argon2id
NONCE_LEN = 12 # 96-bit nonce, the standard/recommended size for AES-GCM
# -----------------------------------------------------------------------
# Data model
# -----------------------------------------------------------------------
@dataclass
class Credential:
"""One saved login entry inside the vault.
Attributes
----------
service:
Human-readable name of the site/app this login is for,
e.g. "github.com". Used as the lookup key.
username:
The username or email associated with this login.
password:
The plaintext password for this login. This is only ever
plaintext in memory, AFTER the vault has been decrypted.
It is never written to disk unencrypted.
notes:
Optional free-text field for anything else worth remembering.
"""
service: str
username: str
password: str
notes: str = ""
def to_dict(self) -> dict[str, str]:
"""Convert this credential to a plain dict for JSON serialization."""
return {
"service": self.service,
"username": self.username,
"password": self.password,
"notes": self.notes,
}
@staticmethod
def from_dict(data: dict[str, str]) -> "Credential":
"""Rebuild a Credential from a dict (the inverse of to_dict)."""
return Credential(
service=data["service"],
username=data["username"],
password=data["password"],
notes=data.get("notes", ""),
)
@dataclass
class Vault:
"""The decrypted, in-memory contents of the password vault.
This object only ever exists in memory after a successful unlock.
It is never itself written to disk — instead, its JSON-serialized
form is what gets encrypted before being written to disk.
"""
credentials: list[Credential] = field(default_factory=list)
def find(self, service: str) -> Credential | None:
"""Look up a credential by service name (case-insensitive)."""
service_lower = service.lower()
for cred in self.credentials:
if cred.service.lower() == service_lower:
return cred
return None
def upsert(self, credential: Credential) -> None:
"""Add a new credential, or overwrite an existing one with the
same service name."""
existing = self.find(credential.service)
if existing is not None:
self.credentials.remove(existing)
self.credentials.append(credential)
def delete(self, service: str) -> bool:
"""Remove a credential by service name. Returns True if something
was actually deleted."""
existing = self.find(service)
if existing is None:
return False
self.credentials.remove(existing)
return True
def to_json_bytes(self) -> bytes:
"""Serialize all credentials to UTF-8 encoded JSON bytes.
This is the plaintext that gets fed into AES-GCM for encryption.
"""
payload = {"credentials": [c.to_dict() for c in self.credentials]}
return json.dumps(payload).encode("utf-8")
@staticmethod
def from_json_bytes(data: bytes) -> "Vault":
"""Rebuild a Vault from decrypted JSON bytes (the inverse of
to_json_bytes)."""
payload = json.loads(data.decode("utf-8"))
creds = [Credential.from_dict(c) for c in payload.get("credentials", [])]
return Vault(credentials=creds)
# -----------------------------------------------------------------------
# Cryptography helpers
# -----------------------------------------------------------------------
def derive_key(master_password: str, salt: bytes) -> bytes:
"""Derive a 256-bit AES key from the master password using Argon2id.
Parameters
----------
master_password:
The user's plaintext master password. Never stored anywhere.
salt:
Random bytes unique to this vault. Storing a unique salt per
vault means two people with the same master password still end
up with completely different encryption keys, and it defeats
precomputed "rainbow table" style attacks.
Returns
-------
bytes
A 32-byte key suitable for use with AES-256-GCM.
"""
return hash_secret_raw(
secret=master_password.encode("utf-8"),
salt=salt,
time_cost=ARGON2_TIME_COST,
memory_cost=ARGON2_MEMORY_COST_KIB,
parallelism=ARGON2_PARALLELISM,
hash_len=ARGON2_HASH_LEN,
type=Type.ID, # Argon2id: hybrid of Argon2i and Argon2d, the
# current recommended variant for password hashing.
)
def encrypt_vault(vault: Vault, master_password: str) -> dict[str, str]:
"""Encrypt a Vault under the given master password.
Generates a fresh random salt and nonce every time this is called,
derives a key from the master password, and encrypts the vault's
JSON representation with AES-256-GCM.
Returns
-------
dict
A JSON-serializable dict containing the base64-encoded salt,
nonce, and ciphertext. This is exactly what gets written to
the vault file on disk.
"""
salt = secrets.token_bytes(SALT_LEN)
nonce = secrets.token_bytes(NONCE_LEN)
key = derive_key(master_password, salt)
aesgcm = AESGCM(key)
plaintext = vault.to_json_bytes()
# AES-GCM's "associated data" parameter is left as None here — we have
# no extra header fields that need to be authenticated but not
# encrypted. The GCM tag is automatically appended to the ciphertext.
ciphertext = aesgcm.encrypt(nonce, plaintext, None)
return {
"kdf": "argon2id",
"cipher": "aes-256-gcm",
"kdf_salt": base64.b64encode(salt).decode("ascii"),
"nonce": base64.b64encode(nonce).decode("ascii"),
"ciphertext": base64.b64encode(ciphertext).decode("ascii"),
}
def decrypt_vault(file_data: dict[str, Any], master_password: str) -> Vault:
"""Decrypt vault file contents back into a Vault object.
Raises
------
InvalidMasterPasswordError
If the master password is wrong, or the file has been tampered
with. AES-GCM cannot tell these two cases apart, and neither
can we — which is the correct, safe behavior. We deliberately
do not leak which case occurred, since that distinction is not
useful to an attacker-safe error message.
"""
salt = base64.b64decode(file_data["kdf_salt"])
nonce = base64.b64decode(file_data["nonce"])
ciphertext = base64.b64decode(file_data["ciphertext"])
key = derive_key(master_password, salt)
aesgcm = AESGCM(key)
try:
plaintext = aesgcm.decrypt(nonce, ciphertext, None)
except InvalidTag as exc:
raise InvalidMasterPasswordError(
"Incorrect master password, or the vault file is corrupted/tampered with."
) from exc
return Vault.from_json_bytes(plaintext)
class InvalidMasterPasswordError(Exception):
"""Raised when vault decryption fails: wrong password OR tampered file."""
# -----------------------------------------------------------------------
# Vault file I/O
# -----------------------------------------------------------------------
def load_vault_file(path: Path) -> dict[str, Any]:
"""Read and JSON-parse the raw (still-encrypted) vault file."""
with path.open("r", encoding="utf-8") as f:
return json.load(f)
def save_vault_file(path: Path, file_data: dict[str, str]) -> None:
"""Write the encrypted vault dict to disk atomically.
We write to a temporary file first, then rename it over the real
vault file. On POSIX systems, rename is atomic, so a crash or power
loss mid-write can't leave you with a half-written, corrupted vault.
"""
path.parent.mkdir(parents=True, exist_ok=True)
tmp_path = path.with_suffix(".tmp")
with tmp_path.open("w", encoding="utf-8") as f:
json.dump(file_data, f, indent=2)
tmp_path.replace(path)
def vault_exists(path: Path) -> bool:
return path.exists()
# -----------------------------------------------------------------------
# CLI command handlers
# -----------------------------------------------------------------------
def prompt_master_password(confirm: bool = False) -> str:
"""Prompt the user for their master password without echoing it to
the screen. If confirm=True, ask twice and verify they match (used
when creating a brand-new vault)."""
password = getpass.getpass("Master password: ")
if confirm:
again = getpass.getpass("Confirm master password: ")
if password != again:
print("Passwords did not match.", file=sys.stderr)
sys.exit(1)
return password
def cmd_init(args: argparse.Namespace) -> None:
"""Create a brand-new, empty vault."""
path = Path(args.vault)
if vault_exists(path):
print(f"A vault already exists at {path}. Refusing to overwrite.", file=sys.stderr)
sys.exit(1)
print("Creating a new vault.")
master_password = prompt_master_password(confirm=True)
empty_vault = Vault()
file_data = encrypt_vault(empty_vault, master_password)
save_vault_file(path, file_data)
print(f"Vault created at {path}")
def cmd_add(args: argparse.Namespace) -> None:
"""Add (or overwrite) a credential in the vault."""
path = Path(args.vault)
_require_vault_exists(path)
master_password = prompt_master_password()
file_data = load_vault_file(path)
vault = decrypt_vault(file_data, master_password)
password = getpass.getpass(f"Password for {args.service}: ")
credential = Credential(
service=args.service,
username=args.username,
password=password,
notes=args.notes or "",
)
vault.upsert(credential)
new_file_data = encrypt_vault(vault, master_password)
save_vault_file(path, new_file_data)
print(f"Saved credentials for '{args.service}'.")
def cmd_get(args: argparse.Namespace) -> None:
"""Retrieve and print a single credential."""
path = Path(args.vault)
_require_vault_exists(path)
master_password = prompt_master_password()
file_data = load_vault_file(path)
vault = decrypt_vault(file_data, master_password)
credential = vault.find(args.service)
if credential is None:
print(f"No entry found for '{args.service}'.", file=sys.stderr)
sys.exit(1)
print(f"Service: {credential.service}")
print(f"Username: {credential.username}")
print(f"Password: {credential.password}")
if credential.notes:
print(f"Notes: {credential.notes}")
def cmd_list(args: argparse.Namespace) -> None:
"""List every saved service name (but never passwords) in the vault."""
path = Path(args.vault)
_require_vault_exists(path)
master_password = prompt_master_password()
file_data = load_vault_file(path)
vault = decrypt_vault(file_data, master_password)
if not vault.credentials:
print("Vault is empty.")
return
print(f"{len(vault.credentials)} saved entries:")
for credential in sorted(vault.credentials, key=lambda c: c.service.lower()):
print(f" - {credential.service} (user: {credential.username})")
def cmd_delete(args: argparse.Namespace) -> None:
"""Delete a credential from the vault."""
path = Path(args.vault)
_require_vault_exists(path)
master_password = prompt_master_password()
file_data = load_vault_file(path)
vault = decrypt_vault(file_data, master_password)
if not vault.delete(args.service):
print(f"No entry found for '{args.service}'.", file=sys.stderr)
sys.exit(1)
new_file_data = encrypt_vault(vault, master_password)
save_vault_file(path, new_file_data)
print(f"Deleted entry for '{args.service}'.")
def cmd_generate(args: argparse.Namespace) -> None:
"""Generate a cryptographically random password and print it.
Uses `secrets`, Python's CSPRNG module built for security-sensitive
randomness (unlike the `random` module, which is NOT safe for
generating secrets).
"""
alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
if args.symbols:
alphabet += "!@#$%^&*()-_=+[]{}"
password = "".join(secrets.choice(alphabet) for _ in range(args.length))
print(password)
def _require_vault_exists(path: Path) -> None:
if not vault_exists(path):
print(
f"No vault found at {path}. Run `password-manager init` first.",
file=sys.stderr,
)
sys.exit(1)
# -----------------------------------------------------------------------
# Argument parsing / entry point
# -----------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
parser = argparse.ArgumentParser(
prog="password-manager",
description="A local, encrypted command-line password manager.",
)
parser.add_argument(
"--vault",
default=str(DEFAULT_VAULT_PATH),
help=f"Path to the vault file (default: {DEFAULT_VAULT_PATH})",
)
subparsers = parser.add_subparsers(dest="command", required=True)
subparsers.add_parser("init", help="Create a new, empty vault.")
add_parser = subparsers.add_parser("add", help="Add or update a credential.")
add_parser.add_argument("service", help="Name of the service, e.g. github.com")
add_parser.add_argument("username", help="Username or email for this login")
add_parser.add_argument("--notes", help="Optional notes about this entry")
get_parser = subparsers.add_parser("get", help="Retrieve a saved credential.")
get_parser.add_argument("service", help="Name of the service to look up")
subparsers.add_parser("list", help="List all saved service names.")
delete_parser = subparsers.add_parser("delete", help="Delete a saved credential.")
delete_parser.add_argument("service", help="Name of the service to delete")
gen_parser = subparsers.add_parser("generate", help="Generate a random password.")
gen_parser.add_argument(
"--length", type=int, default=20, help="Password length (default: 20)"
)
gen_parser.add_argument(
"--symbols", action="store_true", help="Include symbol characters"
)
return parser
COMMANDS = {
"init": cmd_init,
"add": cmd_add,
"get": cmd_get,
"list": cmd_list,
"delete": cmd_delete,
"generate": cmd_generate,
}
def main() -> None:
parser = build_parser()
args = parser.parse_args()
handler = COMMANDS[args.command]
try:
handler(args)
except InvalidMasterPasswordError as exc:
print(f"Error: {exc}", file=sys.stderr)
sys.exit(1)
except KeyboardInterrupt:
print("\nCancelled.", file=sys.stderr)
sys.exit(1)
if __name__ == "__main__":
main()