#  CryptoSack

**CryptoSack** is a CLI tool for **compressing, encrypting, and optionally destroying** entire directories while preserving **permissions, symlinks, empty folders, and metadata**.

Uses `tarfile` + `cryptography` (Fernet / AES-256 in CBC mode) with secure overwriting for destruction.

##  Features

- **Cross-platform** – works on Linux, macOS, and Windows.
- **Streaming** – handles huge archives with low RAM usage.
- **Security** – PBKDF2 with 100,000 iterations + random salt.
- **Integrity** – SHA-256 checksum manifest for verification.
- **Parallel** – multi-threaded compression and shredding.
- **Progress bar** – visual feedback with `tqdm` (optional).
- **Exclusion** – exclude files/directories by pattern.
- **Secure deletion** – 7-pass overwrite + zero pass (optional).
- **Colorized output** – `[INFO]`, `[SUCCESS]`, `WARN`, `ERROR`.

## Installation

git clone https://github.com/payloadare/cryptosack.git
cd cryptosack
pip install -r requirements.txt
chmod +x cryptosack.py
sudo cp cryptosack.py /usr/local/bin/cryptosack   # (optional)

   Usage
Pack (compress + encrypt)


cryptosack pack ./Documents backup.enc

You'll be prompted for a password. SAVE IT – without it you cannot decrypt.

With password inline (not secure!):
bash

cryptosack pack ./Documents backup.enc -p "my_password"

With shredding:


cryptosack pack ./Documents backup.enc --shred

Exclude patterns:


cryptosack pack ./Documents backup.enc --exclude "*.tmp,node_modules,.git"

Unpack (decrypt + extract)


cryptosack unpack backup.enc ./Restore

Enter the password when prompted.
Alias

extract is a synonym for unpack.
Integrity verification

The tool automatically creates a backup.enc.sha256 manifest. During unpack, it verifies every file checksum.
  Test

Run the built-in test suite:

mkdir -p test_src/{subdir,empty_folder}
echo "test" > test_src/file.txt
cryptosack pack test_src test.enc -p "test"
cryptosack unpack test.enc ./out -p "test"
diff -r test_src ./out   # should be empty

  # Requirements

    Python 3.9+

    cryptography

    tqdm (optional, for progress bars)

   License

MIT – see LICENSE.
  # Notes

    --shred overwrites files 7 times before deletion.

    On SSDs with TRIM, overwriting may not be 100% effective.

    Passwords are handled in memory and never written to disk.

  # Author:
## payloadare – GitHub :3
