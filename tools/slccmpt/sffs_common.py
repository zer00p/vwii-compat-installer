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
        has_vwii_dirs = any(os.path.isdir(os.path.join(target_path, d)) for d in ["title", "sys", "shared1", "shared2", "ticket", "import", "meta", "wfs"])
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

def parse_setting_txt_area(decrypted_text):
    if not decrypted_text:
        return None
    for line in decrypted_text.splitlines():
        line = line.strip()
        if line.startswith("AREA="):
            return line.split("=", 1)[1].strip()
    return None

COMMON_STOCK_SYSTEM_TITLES = {
    0x0000000100000002: "System Menu (vWii)",
    0x0000000100000050: "IOS80",
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
    0x0001000248414241: "Disc Channel (HABA)",
    0x0001000248414341: "Mii Channel (HACA)",
    0x0001000248435641: "Return to Wii U Menu (HCVA)",
}

REGION_STOCK_TITLES = {
    "JPN": {
        0x000100024843554a: "Wii U Electronic Manual JPN (HCUJ)",
        0x0001000848414c4a: "EULA JPN (HALJ)",
        0x0001000848435a4a: "Region Select JPN (HCZJ)",
    },
    "USA": {
        0x0001000248435545: "Wii U Electronic Manual USA (HCUE)",
        0x0001000848414c45: "EULA USA (HALE)",
        0x0001000848435a45: "Region Select USA (HCZE)",
    },
    "EUR": {
        0x0001000248435550: "Wii U Electronic Manual EUR (HCUP)",
        0x0001000848414c50: "EULA EUR (HALP)",
        0x0001000848435a50: "Region Select EUR (HCZP)",
    },
}

def get_stock_titles(region="JPN"):
    titles = dict(COMMON_STOCK_SYSTEM_TITLES)
    reg = (region or "").upper()
    if reg in REGION_STOCK_TITLES:
        titles.update(REGION_STOCK_TITLES[reg])
    return titles

def is_original_nintendo_signature(sig):
    if not sig:
        return False
    zero_count = sig.count(b'\x00') if isinstance(sig, (bytes, bytearray)) else list(sig).count(0)
    return zero_count < (len(sig) // 2)

def parse_certificates(cert_data):
    """
    Parses concatenated binary certificates (from /sys/cert.sys or WAD/NUS) into a dictionary
    keyed by certificate name (e.g. 'CA00000001', 'CP00000004', 'XS00000003').
    """
    if not cert_data:
        return {}
    certs = {}
    pos = 0
    while pos + 4 <= len(cert_data):
        sig_type = struct.unpack('>I', cert_data[pos:pos+4])[0]
        if sig_type == 0x00010000: # RSA4096 (0x400 bytes)
            cert_len = 0x400
            if pos + cert_len > len(cert_data):
                break
            sig = cert_data[pos+4:pos+4+512]
            issuer = cert_data[pos+0x240:pos+0x240+64].rstrip(b'\x00').decode('latin1', 'replace')
            key_type = struct.unpack('>I', cert_data[pos+0x280:pos+0x280+4])[0]
            name = cert_data[pos+0x284:pos+0x284+64].rstrip(b'\x00').decode('latin1', 'replace')
            modulus = cert_data[pos+0x2C8:pos+0x2C8+256]
            exponent = struct.unpack('>I', cert_data[pos+0x3C8:pos+0x3C8+4])[0]
            n = int.from_bytes(modulus, 'big')
            certs[name] = {
                'sig_type': sig_type, 'sig': sig, 'issuer': issuer, 'key_type': key_type,
                'name': name, 'n': n, 'e': exponent, 'modulus': modulus, 'size': cert_len,
                'raw': cert_data[pos:pos+cert_len]
            }
            pos += cert_len
        elif sig_type == 0x00010001: # RSA2048 (0x300 bytes)
            cert_len = 0x300
            if pos + cert_len > len(cert_data):
                break
            sig = cert_data[pos+4:pos+4+256]
            issuer = cert_data[pos+0x140:pos+0x140+64].rstrip(b'\x00').decode('latin1', 'replace')
            key_type = struct.unpack('>I', cert_data[pos+0x180:pos+0x180+4])[0]
            name = cert_data[pos+0x184:pos+0x184+64].rstrip(b'\x00').decode('latin1', 'replace')
            modulus = cert_data[pos+0x1C8:pos+0x1C8+256]
            exponent = struct.unpack('>I', cert_data[pos+0x2C8:pos+0x2C8+4])[0]
            n = int.from_bytes(modulus, 'big')
            certs[name] = {
                'sig_type': sig_type, 'sig': sig, 'issuer': issuer, 'key_type': key_type,
                'name': name, 'n': n, 'e': exponent, 'modulus': modulus, 'size': cert_len,
                'raw': cert_data[pos:pos+cert_len]
            }
            pos += cert_len
        elif sig_type == 0x00010002: # ECDSA
            cert_len = 0x180
            pos += cert_len
        else:
            break
    return certs

def is_retail_certificate(cert):
    if not cert:
        return False
    name = cert.get('name', '')
    issuer = cert.get('issuer', '')
    sig_type = cert.get('sig_type', 0)
    size = cert.get('size', 0)
    if name == 'XS00000003' and issuer == 'Root-CA00000001' and sig_type == 0x00010001 and size == 0x300:
        return True
    if name == 'CA00000001' and issuer == 'Root' and sig_type == 0x00010000 and size == 0x400:
        return True
    if name == 'CP00000004' and issuer == 'Root-CA00000001' and sig_type == 0x00010001 and size == 0x300:
        return True
    return False

def verify_rsa_signature(sig, payload, cert):
    """
    Verifies an RSA PKCS#1 v1.5 SHA-1 signature against a parsed certificate.
    Returns True if authentic and valid, False otherwise.
    """
    if not cert or not sig or not payload:
        return False
    n = cert.get('n', 0)
    e = cert.get('e', 0)
    if n == 0 or e == 0:
        return False
    
    sig_int = int.from_bytes(sig, 'big')
    if sig_int == 0:
        return False # Zero-filled signature (tampered / forged)
        
    try:
        x = pow(sig_int, e, n)
        x_bytes = x.to_bytes(len(sig), 'big')
        ber = b'\x00\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
        h = hashlib.sha1(payload).digest()
        expected = b'\x00\x01' + (b'\xFF' * (len(sig) - 38)) + ber + h
        return x_bytes == expected
    except Exception:
        return False

def parse_tmd(tmd_data):
    """
    Parses a TitleTmd binary blob.
    Returns dict with signature, issuer, signer cert name, titleId, version, groupId,
    numContents, and list of content records.
    """
    if not tmd_data or len(tmd_data) < 0x1E4:
        return None
    sig_type = struct.unpack('>I', tmd_data[:4])[0]
    payload_off = 0x240 if sig_type == 0x00010000 else 0x140
    sig_len = 512 if sig_type == 0x00010000 else 256
    sig = tmd_data[4:4+sig_len]
    payload = tmd_data[payload_off:]
    issuer = tmd_data[payload_off:payload_off+64].rstrip(b'\x00').decode('latin1', 'replace')
    signer = issuer.split('-')[-1] if issuer else ''
    
    t_title_id, t_type, t_group_id = struct.unpack('>QIH', tmd_data[payload_off+0x4C:payload_off+0x4C+14])
    t_ver, t_num_contents = struct.unpack('>HH', tmd_data[payload_off+0x9C:payload_off+0x9C+4])
    contents = []
    contents_start = payload_off + 0xA4
    for c in range(t_num_contents):
        rec_off = contents_start + c * 36
        if rec_off + 36 > len(tmd_data):
            break
        cid, cidx, ctype, csize = struct.unpack('>IHHQ', tmd_data[rec_off:rec_off+16])
        chash = tmd_data[rec_off+16:rec_off+36]
        contents.append({
            'cid': cid,
            'index': cidx,
            'type': ctype,
            'size': csize,
            'hash': chash,
            'hash_hex': chash.hex(),
            'is_shared': bool(ctype & 0x8000)
        })
    return {
        'sig_type': sig_type,
        'sig': sig,
        'payload': payload,
        'issuer': issuer,
        'signer': signer,
        'title_id': t_title_id,
        'title_type': t_type,
        'group_id': t_group_id,
        'version': t_ver,
        'num_contents': t_num_contents,
        'contents': contents
    }

def parse_ticket(tik_data):
    """
    Parses a TitleTicket binary blob.
    Returns dict with signature, issuer, signer cert name, titleId, ticketId, consoleId, etc.
    """
    if not tik_data or len(tik_data) < 0x2A4:
        return None
    sig_type = struct.unpack('>I', tik_data[:4])[0]
    payload_off = 0x240 if sig_type == 0x00010000 else 0x140
    sig_len = 512 if sig_type == 0x00010000 else 256
    sig = tik_data[4:4+sig_len]
    payload = tik_data[payload_off:]
    issuer = tik_data[payload_off:payload_off+64].rstrip(b'\x00').decode('latin1', 'replace')
    signer = issuer.split('-')[-1] if issuer else ''
    ticket_id, console_id, t_title_id = struct.unpack('>QIQ', tik_data[payload_off+0x90:payload_off+0x90+20])
    return {
        'sig_type': sig_type,
        'sig': sig,
        'payload': payload,
        'issuer': issuer,
        'signer': signer,
        'ticket_id': ticket_id,
        'console_id': console_id,
        'title_id': t_title_id
    }
