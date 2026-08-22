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

def decode_mode_perms(mode):
    """
    Decodes an SFFS/ISFS 8-bit mode byte into a 9-character Unix-like permission string.
    ISFS permissions only have Read and Write bits (no execute bits):
      Bits 7..6: Owner (3=rw, 2=w, 1=r, 0=none)
      Bits 5..4: Group (3=rw, 2=w, 1=r, 0=none)
      Bits 3..2: Other (3=rw, 2=w, 1=r, 0=none)
    """
    perm_map = {0: "---", 1: "r--", 2: "-w-", 3: "rw-"}
    owner = perm_map[(mode >> 6) & 3]
    group = perm_map[(mode >> 4) & 3]
    other = perm_map[(mode >> 2) & 3]
    return f"{owner}{group}{other}"

def decode_mode(mode):
    """Convenience alias for decode_mode_perms."""
    return decode_mode_perms(mode)

def find_otp_key(custom_otp_path=None, target_path=None):
    candidates = []
    if custom_otp_path:
        candidates.append(custom_otp_path)

    if target_path:
        target_abs = os.path.abspath(target_path)
        if os.path.isdir(target_abs):
            candidates.append(os.path.join(target_abs, "otp.bin"))
            candidates.append(os.path.join(os.path.dirname(target_abs), "otp.bin"))
        else:
            candidates.append(os.path.join(os.path.dirname(target_abs), "otp.bin"))

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

def resolve_target(target_path):
    if not os.path.exists(target_path):
        raise FileNotFoundError(f"Target path not found: {target_path}")

    if os.path.isfile(target_path):
        return os.path.abspath(target_path), 'image'

    if os.path.isdir(target_path):
        # Check if the directory itself is directly an extracted vWii root directory
        has_vwii_dirs = any(os.path.isdir(os.path.join(target_path, d)) for d in ["title", "sys", "shared1", "shared2", "ticket", "import"])
        if has_vwii_dirs:
            return os.path.abspath(target_path), 'extracted_dir'

        raise ValueError(
            f"Directory '{target_path}' is not an extracted vWii root (missing /title, /sys, /shared1). "
            f"Please point directly to the SLCCMPT .raw image file or the extracted root folder."
        )

    raise ValueError(f"'{target_path}' is not a valid SLCCMPT image file or extracted vWii root directory.")

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
    key, hmac_key = find_otp_key(otp_path, image_path)
    size = os.path.getsize(image_path)
    nand = NANDFormatSpare(image_path) if size == 553648128 else NANDFormatBare(image_path)
    nand.set_keys(key, hmac_key)
    sb_cluster, sb_ver = find_newest_sffs(nand)
    if sb_cluster is None:
        raise ValueError(f"No valid SFFS superblock found in {image_path}")
    sb = SFFS(read_superblock(nand, sb_cluster))
    root_entry = SFFS_entry(sb.fst, sb.fat, 0, "")
    return nand, sb, root_entry

def load_target(target_path, otp_path=None):
    resolved_path, target_type = resolve_target(target_path)
    if target_type == 'image':
        nand, sb, root_entry = load_sffs(resolved_path, otp_path)
        return target_type, resolved_path, nand, sb, root_entry
    else:
        return target_type, resolved_path, None, None, None

def read_entry_content(nand, entry):
    if not bool(entry.mode & 1):
        return None
    chain = entry.get_cluster_chain()
    buf = bytearray()
    for cl in chain:
        buf.extend(nand.decrypt_cluster(cl))
    return bytes(buf[:entry.size])

def walk_extracted_tree(base_dir, entries_dict, read_content=False):
    base_dir = os.path.abspath(base_dir)
    for root, dirs, files in os.walk(base_dir):
        rel_root = os.path.relpath(root, base_dir)
        vpath_root = "/" if rel_root == "." else "/" + rel_root.replace("\\", "/")

        if vpath_root != "/":
            entries_dict[vpath_root] = {
                "path": vpath_root,
                "name": os.path.basename(vpath_root),
                "is_file": False,
                "mode": 0xfe,
                "attr": 0,
                "uid": 0,
                "gid": 0,
                "size": 0,
                "content": None,
                "sha1": None,
                "from_extracted": True,
                "has_stock_perms": False
            }

        for f in files:
            fpath = os.path.join(root, f)
            vpath_file = os.path.join(vpath_root, f).replace("\\", "/")
            if not vpath_file.startswith("/"):
                vpath_file = "/" + vpath_file

            size = os.path.getsize(fpath)
            content = None
            sha1 = None
            if read_content or size < 100 * 1024 * 1024:
                try:
                    with open(fpath, "rb") as fp:
                        content = fp.read()
                    sha1 = hashlib.sha1(content).hexdigest()
                except Exception:
                    pass

            entries_dict[vpath_file] = {
                "path": vpath_file,
                "name": f,
                "fpath": fpath,
                "is_file": True,
                "mode": 0xf1,
                "attr": 0,
                "uid": 0,
                "gid": 0,
                "size": size,
                "content": content,
                "sha1": sha1,
                "from_extracted": True,
                "has_stock_perms": False
            }

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
        "sha1": sha1,
        "entry": entry
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

KNOWN_TITLE_NAMES = {
    0x0000000100000002: "System Menu (vWii)",
    0x0000000100000050: "IOS80",
    0x0001000248435550: "Wii U Electronic Manual EUR (HCUP)",
    0x0001000248435545: "Wii U Electronic Manual USA (HCUE)",
    0x000100024843554a: "Wii U Electronic Manual JPN (HCUJ)",
    0x0001000248414341: "Mii Channel (HACA)",
    0x0001000848414c50: "EULA EUR (HALP)",
    0x0001000848414c45: "EULA USA (HALE)",
    0x0001000848414c4a: "EULA JPN (HALJ)",
    0x0001000248435641: "Return to Wii U Menu (HCVA)",
    0x0001000248414241: "Disc Channel (HABA)",
    0x0000000100000200: "BC-NAND",
    0x0000000100000201: "BC-WFS",
    0x0000000100000009: "IOS9",
    0x000000010000000c: "IOS12",
    0x000000010000000d: "IOS13",
    0x000000010000000e: "IOS14",
    0x000000010000000f: "IOS15",
    0x0000000100000011: "IOS17",
    0x0000000100000015: "IOS21",
    0x0000000100000016: "IOS22",
    0x000000010000001c: "IOS28",
    0x000000010000001f: "IOS31",
    0x0000000100000021: "IOS33",
    0x0000000100000022: "IOS34",
    0x0000000100000023: "IOS35",
    0x0000000100000024: "IOS36",
    0x0000000100000025: "IOS37",
    0x0000000100000026: "IOS38",
    0x0000000100000029: "IOS41",
    0x000000010000002b: "IOS43",
    0x000000010000002d: "IOS45",
    0x000000010000002e: "IOS46",
    0x0000000100000030: "IOS48",
    0x0000000100000035: "IOS53",
    0x0000000100000037: "IOS55",
    0x0000000100000038: "IOS56",
    0x0000000100000039: "IOS57",
    0x000000010000003a: "IOS58",
    0x000000010000003b: "IOS59",
    0x000000010000003e: "IOS62",
    0x0001000848435a50: "Region Select EUR (HCZP)",
    0x0001000848435a45: "Region Select USA (HCZE)",
    0x0001000848435a4a: "Region Select JPN (HCZJ)",
}

def is_system_title(title_id):
    idHi = (title_id >> 32) & 0xFFFFFFFF
    if idHi == 0x00000001:
        return True
    return title_id in KNOWN_TITLE_NAMES

def get_system_title_gid(title_id):
    if title_id == 0x0001000248435641: # HCVA (Return to Wii U)
        return 23130 # 0x5a5a ('ZZ')
    idHi = (title_id >> 32) & 0xFFFFFFFF
    if idHi == 0x00000001:
        return 1 # System titles & IOSes
    if title_id in KNOWN_TITLE_NAMES:
        return 12337 # 0x3031 ('01') Channels, Hidden Channels
    return 12337

def parse_tmd_group_id(tmd_data):
    if not tmd_data or len(tmd_data) < 0x1E4:
        return None
    sig_type = struct.unpack(">I", tmd_data[:4])[0]
    if sig_type == 0x00010000: # RSA4096
        payload_offset = 0x240
    elif sig_type == 0x00010001: # RSA2048
        payload_offset = 0x140
    elif sig_type == 0x00010002: # ECDSA
        payload_offset = 0x80
    else:
        payload_offset = 0x140
    if len(tmd_data) < payload_offset + 0x5A:
        return None
    return struct.unpack(">H", tmd_data[payload_offset + 0x58 : payload_offset + 0x5A])[0]

def get_expected_gid(title_id, tmd_data=None):
    if is_system_title(title_id):
        return get_system_title_gid(title_id)
    if tmd_data:
        gid = parse_tmd_group_id(tmd_data)
        if gid is not None:
            return gid
    return 12337

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
