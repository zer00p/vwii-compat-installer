#!/usr/bin/env python3
"""
Common SFFS / SLCCMPT reader utilities for vWii NAND images.
Provides NAND loading, SFFS filesystem parsing, and decryption routines.
"""

import os
import sys
import struct
import hashlib
import types

# Ensure pycryptodome / cryptography fallback
try:
    import Crypto
    from Crypto.Cipher import AES
except ImportError:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    class AESMock:
        MODE_CBC = 'CBC'
        MODE_ECB = 'ECB'
        @staticmethod
        def new(key, mode, iv=b"\x00"*16):
            if mode == 'CBC':
                c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            elif mode == 'ECB':
                c = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            return AESMock(c)
        def __init__(self, cipher):
            self.cipher = cipher
        def decrypt(self, data):
            dec = self.cipher.decryptor()
            return dec.update(data) + dec.finalize()
        def encrypt(self, data):
            enc = self.cipher.encryptor()
            return enc.update(data) + enc.finalize()
    crypto_mod = types.ModuleType('Crypto')
    cipher_mod = types.ModuleType('Crypto.Cipher')
    cipher_mod.AES = AESMock
    crypto_mod.Cipher = cipher_mod
    sys.modules['Crypto'] = crypto_mod
    sys.modules['Crypto.Cipher'] = cipher_mod

# Locate and import local nand module
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

from nand import NANDFormatSpare, NANDFormatBare, SFFS, SFFS_entry, read_superblock, TOTAL_CLUSTER, NUM_SUPER, CLUSTER_PER_SUPER

# SFFS Mode to POSIX string mapping
MODE_MAP = {
    0xf1: "rw-rw---- (0660 system file)",
    0xf2: "rwxrwx--- (0770 content/ticket/sys dir)",
    0xf5: "rw-rw-r-- (0664 cert.sys)",
    0xf6: "rwxrwxr-x (0775 system hierarchy dir)",
    0xc2: "rwx------ (0700 title data dir)",
    0x55: "r--r--r-- (0444 setting.txt)",
    0xfe: "rwxrwxrwx (0777 shared2/tmp dir)",
    0x02: "--------- (0000 ticket subdir)",
}

def decode_mode(mode):
    return MODE_MAP.get(mode, f"0x{mode:02x}")

def find_otp_key(custom_otp_path=None):
    candidates = []
    if custom_otp_path:
        candidates.append(custom_otp_path)
    candidates.extend([
        os.path.join(project_root, "testdata", "otp.bin"),
        os.path.join(project_root, "testdata", "betwiinu", "otp.bin"),
        os.path.join(script_dir, "otp.bin"),
        "otp.bin"
    ])
    for p in candidates:
        if os.path.exists(p) and os.path.getsize(p) >= 0x100:
            with open(p, 'rb') as f:
                data = f.read()
                # Wii U OTP: vWii NAND AES key is at offset 0x058
                # Legacy Wii OTP: NAND AES key is at offset 0x170
                if len(data) >= 0x068 and any(b != 0 for b in data[0x058:0x068]):
                    key = data[0x058:0x068]
                elif len(data) >= 0x180:
                    key = data[0x170:0x180]
                else:
                    key = b"\x00" * 16

                hmac_key = data[0x1E0:0x1F4] if len(data) >= 0x1F4 else b"\x00" * 20
            return key, hmac_key
    raise FileNotFoundError(f"Could not find valid otp.bin. Please specify with --otp.")

def find_newest_sffs(nand):
    highest_version = 0
    highest_cluster = None
    for c in range(TOTAL_CLUSTER - NUM_SUPER * CLUSTER_PER_SUPER, TOTAL_CLUSTER, CLUSTER_PER_SUPER):
        raw = read_superblock(nand, c)
        if raw[:4] not in (b"SFS!", b"SFFS"):
            continue
        sb = SFFS(raw)
        version = sb.version()
        if version > highest_version:
            highest_version = version
            highest_cluster = c
    return highest_cluster, highest_version

def load_sffs(image_path, otp_path=None):
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image not found: {image_path}")
    key, hmac_key = find_otp_key(otp_path)
    size = os.path.getsize(image_path)
    nand = NANDFormatSpare(image_path) if size == 553648128 else NANDFormatBare(image_path)
    nand.set_keys(key, hmac_key)
    sb_cluster, sb_ver = find_newest_sffs(nand)
    if sb_cluster is None:
        raise ValueError(f"No valid SFFS superblock found in {image_path}")
    sb = SFFS(read_superblock(nand, sb_cluster))
    root_entry = SFFS_entry(sb.fst, sb.fat, 0, "")
    return nand, sb, root_entry

def read_entry_content(nand, entry):
    if not bool(entry.mode & 1):
        return None
    chain = entry.get_cluster_chain()
    buf = bytearray()
    for cl in chain:
        buf.extend(nand.decrypt_cluster(cl))
    return bytes(buf[:entry.size])

def walk_sffs_tree(nand, entry, entries_dict, read_content=False):
    full_path = (entry.path + entry.name)
    if not full_path:
        full_path = "/"
    elif not full_path.startswith("/"):
        full_path = "/" + full_path

    is_file = bool(entry.mode & 1)
    content = None
    sha1 = None
    if is_file and read_content:
        content = read_entry_content(nand, entry)
        if content is not None:
            sha1 = hashlib.sha1(content).hexdigest()

    entries_dict[full_path] = {
        "path": full_path,
        "name": entry.name,
        "is_file": is_file,
        "mode": entry.mode,
        "attr": entry.attr,
        "uid": entry.uid,
        "gid": entry.gid,
        "size": entry.size,
        "content": content,
        "sha1": sha1
    }

    if not is_file:
        for child in entry.children():
            walk_sffs_tree(nand, child, entries_dict, read_content)

def parse_uid_sys_table(content):
    if not content:
        return []
    entries = []
    num_entries = len(content) // 12
    for i in range(num_entries):
        off = i * 12
        tid, uid = struct.unpack(">QI", content[off:off+12])
        entries.append((tid, uid))
    return entries

def get_expected_gid(title_id):
    if title_id == 0x0001000248435641: # HCVA (Return to Wii U)
        return 23130 # 0x5a5a ('ZZ')
    idHi = (title_id >> 32) & 0xFFFFFFFF
    if idHi == 0x00000001:
        return 1 # System titles & IOSes
    return 12337 # 0x3031 ('01') Channels, Hidden Channels, Disc titles

def decrypt_setting_txt(raw):
    if not raw or len(raw) < 256:
        return None
    key = 0x73B5DBFA
    out = bytearray()
    for b in raw:
        out.append(b ^ (key & 0xFF))
        key = ((key << 1) | (key >> 31)) & 0xFFFFFFFF
    try:
        return out.decode('latin1', errors='replace')
    except Exception:
        return None
