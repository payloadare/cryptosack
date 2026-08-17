#!/usr/bin/env python3
import os
import sys
import tarfile
import argparse
import getpass
import tempfile
import hashlib
import secrets
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

class Colors:
    INFO = '\033[1;34m'
    SUCCESS = '\033[1;32m'
    WARN = '\033[1;33m'
    ERROR = '\033[1;31m'
    KEY = '\033[1;36m'
    NC = '\033[0m'

def log_info(msg): print(f"{Colors.INFO}[INFO]{Colors.NC} {msg}")
def log_success(msg): print(f"{Colors.SUCCESS}[SUCCESS]{Colors.NC} {msg}")
def log_warn(msg): print(f"{Colors.WARN}[WARN]{Colors.NC} {msg}")
def log_error(msg): print(f"{Colors.ERROR}[ERROR]{Colors.NC} {msg}")

def generate_key(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def calculate_checksum(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

def shred_file(filepath, passes=7):
    try:
        size = os.path.getsize(filepath)
        with open(filepath, 'wb') as f:
            for _ in range(passes):
                f.write(secrets.token_bytes(size))
                f.seek(0)
            f.write(b'\x00' * size)
        os.remove(filepath)
        return True
    except Exception:
        return False

def pack(src_dir, output_file, password, shred=False, exclude=None, verbose=False):
    src_path = Path(src_dir)
    if not src_path.exists() or not src_path.is_dir():
        log_error(f"{src_dir} does not exist or is not a directory")
        sys.exit(1)

    key, salt = generate_key(password)
    fernet = Fernet(key)

    exclude_patterns = exclude.split(',') if exclude else []
    manifest = {}
    total_files = 0

    log_info(f"Scanning {src_dir}...")
    for root, dirs, files in os.walk(src_path):
        for f in files:
            fp = Path(root) / f
            rel = fp.relative_to(src_path)
            if any(str(rel).startswith(p.strip()) for p in exclude_patterns):
                continue
            manifest[str(rel)] = calculate_checksum(fp)
            total_files += 1

    if total_files == 0:
        log_error("No files found to pack")
        sys.exit(1)

    log_info(f"Packing {total_files} files...")

    tar_path = tempfile.mktemp(suffix='.tar')
    try:
        with tarfile.open(tar_path, 'w:gz') as tar:
            if HAS_TQDM:
                iterator = tqdm(list(manifest.keys()), desc="Adding files", unit="file")
            else:
                iterator = manifest.keys()

            for rel_path in iterator:
                full_path = src_path / rel_path
                tar.add(full_path, arcname=str(rel_path), recursive=False)

        log_info("Encrypting...")
        with open(tar_path, 'rb') as f_in:
            data = f_in.read()
            encrypted = fernet.encrypt(data)

        with open(output_file, 'wb') as f_out:
            f_out.write(salt)
            f_out.write(encrypted)

        log_success(f"{output_file} created ({os.path.getsize(output_file) // 1024} KB)")

        with open(f"{output_file}.sha256", 'w') as mf:
            for rel, checksum in manifest.items():
                mf.write(f"{checksum}  {rel}\n")

        if shred:
            log_warn("Shredding original files...")
            log_warn("THIS IS IRREVERSIBLE!")
            confirm = input("Type 'YES' to confirm: ")
            if confirm != "YES":
                log_warn("Shred cancelled")
                return

            if HAS_TQDM:
                file_list = list(src_path.rglob('*'))
                file_list = [f for f in file_list if f.is_file()]
                iterator = tqdm(file_list, desc="Shredding", unit="file")
            else:
                iterator = src_path.rglob('*')
                iterator = [f for f in iterator if f.is_file()]

            failed = 0
            for f in iterator:
                if not shred_file(f):
                    failed += 1

            for root, dirs, files in os.walk(src_path, topdown=False):
                for d in dirs:
                    try:
                        os.rmdir(Path(root) / d)
                    except OSError:
                        pass

            if failed > 0:
                log_warn(f"{failed} files could not be shredded")
            else:
                log_success("Original directory destroyed")

    finally:
        if os.path.exists(tar_path):
            os.remove(tar_path)

def unpack(input_file, dest_dir, password, verbose=False):
    dest_path = Path(dest_dir)
    dest_path.mkdir(parents=True, exist_ok=True)

    if not os.path.exists(input_file):
        log_error(f"{input_file} does not exist")
        sys.exit(1)

    try:
        with open(input_file, 'rb') as f_in:
            salt = f_in.read(16)
            encrypted = f_in.read()

        if len(salt) != 16:
            log_error("Corrupted file: invalid salt")
            sys.exit(1)

        key, _ = generate_key(password, salt)
        fernet = Fernet(key)

        log_info("Decrypting...")
        decrypted = fernet.decrypt(encrypted)

        tar_path = tempfile.mktemp(suffix='.tar')
        with open(tar_path, 'wb') as f_out:
            f_out.write(decrypted)

        log_info(f"Extracting to {dest_dir}...")
        with tarfile.open(tar_path, 'r:gz') as tar:
            members = tar.getmembers()
            if HAS_TQDM:
                for m in tqdm(members, desc="Extracting", unit="file"):
                    tar.extract(m, dest_path, filter='data')
            else:
                tar.extractall(dest_path, filter='data')

        log_success(f"Extracted to {dest_dir}")

        manifest_file = f"{input_file}.sha256"
        if os.path.exists(manifest_file):
            log_info("Verifying integrity...")
            errors = 0
            with open(manifest_file, 'r') as mf:
                for line in mf:
                    if not line.strip():
                        continue
                    expected, rel = line.strip().split('  ')
                    filepath = dest_path / rel
                    if not filepath.exists():
                        log_error(f"Missing: {rel}")
                        errors += 1
                    else:
                        actual = calculate_checksum(filepath)
                        if actual != expected:
                            log_error(f"Checksum mismatch: {rel}")
                            errors += 1
            if errors == 0:
                log_success("Integrity verified")
            else:
                log_error(f"{errors} integrity errors found")

    except Exception as e:
        log_error(f"Decryption failed: {str(e)}")
        sys.exit(1)
    finally:
        if 'tar_path' in locals() and os.path.exists(tar_path):
            os.remove(tar_path)

def interactive_password(prompt):
    return getpass.getpass(prompt)

def main():
    parser = argparse.ArgumentParser(
        description="CryptoSack - Compress, encrypt, and optionally destroy directories",
        epilog="Examples:\n  cryptosack pack ./Documents backup.enc\n  cryptosack unpack backup.enc ./Restore"
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    pack_parser = subparsers.add_parser('pack', help='Compress and encrypt')
    pack_parser.add_argument('src', help='Source directory')
    pack_parser.add_argument('output', help='Output file (.enc)')
    pack_parser.add_argument('-p', '--password', help='Password (will prompt if not provided)')
    pack_parser.add_argument('--shred', action='store_true', help='Destroy original files after packing')
    pack_parser.add_argument('--exclude', help='Comma-separated patterns to exclude')
    pack_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    unpack_parser = subparsers.add_parser('unpack', help='Decrypt and extract')
    unpack_parser.add_argument('input', help='Input file (.enc)')
    unpack_parser.add_argument('dest', nargs='?', default='./Restore', help='Destination directory')
    unpack_parser.add_argument('-p', '--password', help='Password (will prompt if not provided)')
    unpack_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    extract_parser = subparsers.add_parser('extract', help='Alias for unpack')
    extract_parser.add_argument('input', help='Input file (.enc)')
    extract_parser.add_argument('dest', nargs='?', default='./Restore', help='Destination directory')
    extract_parser.add_argument('-p', '--password', help='Password (will prompt if not provided)')
    extract_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.command == 'pack':
        password = args.password
        if not password:
            password = interactive_password("Enter password: ")
            confirm = interactive_password("Confirm password: ")
            if password != confirm:
                log_error("Passwords do not match")
                sys.exit(1)
        if len(password) < 4:
            log_error("Password too short (minimum 4 characters)")
            sys.exit(1)
        pack(args.src, args.output, password, args.shred, args.exclude, args.verbose)

    elif args.command in ['unpack', 'extract']:
        password = args.password
        if not password:
            password = interactive_password("Enter password: ")
        unpack(args.input, args.dest, password, args.verbose)

if __name__ == "__main__":
    main()
