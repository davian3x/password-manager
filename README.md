# password-manager
local, encrypted command-line password manager written in Python.
Your credentials are stored in a single encrypted vault file on disk, protected by one master
password. The master password is never stored — it’s used to re-derive the encryption key
each time you unlock the vault.
How it works
Argon2id derives a 256-bit encryption key from your master password. It’s deliberately
slow and memory-hard, making brute-force attacks on a stolen vault file expensive.
AES-256-GCM encrypts your credentials and authenticates the ciphertext, so
tampering or an incorrect password causes decryption to fail loudly instead of returning
corrupted data.
A random salt (for Argon2id) and nonce (for AES-GCM) are generated on every save and
stored alongside the ciphertext in the vault file.
Install
pip install -e .
Usage
# Create a new vault (prompts for a master password)
password-manager init
# Add a credential
password-manager add github.com myusername --notes "personal account"
# Retrieve a credential
password-manager get github.com
# List all saved service names
password-manager list
# Delete a credential
password-manager delete github.com
# Generate a random password
password-manager generate --length 24 --symbols
By default, the vault lives at ~/.password_manager/vault.json . Use --vault
/path/to/file.json to point at a different location.
Security notes
This is an educational/portfolio project. It has not been audited for production use.
The master password is never written to disk or logged.
Passwords are only ever plaintext in ,