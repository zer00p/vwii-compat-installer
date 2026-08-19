# Betwiin v1.0, Copyright 2009 Haxx Enterprises (bushing@gmail.com)
# Licensed to you under the terms of the GNU GPL v2.0; see http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#!/usr/bin/env python3
import os
import sys
import struct
import hashlib
import hmac
from struct import unpack, pack
from array import array

# Fallback crypto support
try:
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
    class AES:
        MODE_CBC = 'CBC'
        MODE_ECB = 'ECB'
        @staticmethod
        def new(key, mode, iv=b"\x00"*16):
            return AESMock.new(key, mode, iv)

NUM_SUPER = 64
CLUSTER_PER_SUPER = 16
TOTAL_CLUSTER = 0x8000
PAGE_SIZE = 2048
PAGES_PER_CLUSTER = 8
CLUSTER_SIZE = PAGE_SIZE * PAGES_PER_CLUSTER

def pad(s, c, l):
    if len(s) < l:
        s += c * (l - len(s))
    return s

def decrypt_block(key, inblock):
    aes = AES.new(key, AES.MODE_CBC, b"\x00" * 16)
    return aes.decrypt(inblock)

def encrypt_block(key, inblock):
    aes = AES.new(key, AES.MODE_CBC, b"\x00" * 16)
    return aes.encrypt(inblock)

def CountBits(c):
    count = 0
    mask = 1
    for i in range(8):
        count = count + ((mask & c) != 0)
        mask = mask << 1
    return count

def parity(c):
    return CountBits(c) % 2

def all_zeros(data: bytes):
    for b in data:
        if b:
            return False
    return True

def calc_ecc(data):
    a0 = array('B', [0]*12)
    a1 = array('B', [0]*12)

    for i, x in enumerate(data):
        for j in range(9):
            if ((i >> j) & 1) == 1:
                a1[3+j] ^= x
            else:
                a0[3+j] ^= x

    x = a0[3] ^ a1[3]
    a0[0] = x & 0x55
    a1[0] = x & 0xaa
    a0[1] = x & 0x33
    a1[1] = x & 0xcc
    a0[2] = x & 0x0f
    a1[2] = x & 0xf0

    for j in range(12):
        a0[j] = parity(a0[j])
        a1[j] = parity(a1[j])

    r0 = 0
    r1 = 0
    for j in range(12):
        r0 |= a0[j] << j
        r1 |= a1[j] << j

    return struct.pack("<HH", r0, r1)

class NANDFormat:
    def calc_page_ecc(self, page):
        retval = bytearray()
        data = self.get_page(page)
        for i in range(4):
            retval.extend(calc_ecc(data[512*i:512*(i+1)]))
        return retval

    def get_stored_ecc(self, page):
        return self.get_spare(page)[48:64]

    def get_cluster(self, cluster_no: int) -> bytearray:
        retval = bytearray()
        for i in range(0, 8):
            page = self.get_page(cluster_no * 8 + i)
            retval.extend(page)
        return retval

    def decrypt_cluster(self, cluster_no):
        return decrypt_block(self.aes_key, self.get_cluster(cluster_no))

    def get_cluster_hmac(self, cluster_no):
        return self.get_spare(cluster_no * 8 + 6)[1:21]

    def set_keys(self, aes, hmac):
        self.aes_key = aes
        self.hmac_key = hmac

class NANDFormatBare(NANDFormat):
    spare_supported = False
    badblock_supported = False

    def __init__(self, file):
        self.f = open(file, "rb")
        self.f.seek(0, os.SEEK_END)
        self.fsize = self.f.tell()
        self.f.seek(0, os.SEEK_SET)
        self.blocksize = 64
        self.aes_key = b""
        self.hmac_key = b""

        if self.fsize % 2048 != 0:
            raise ValueError("File size not divisible by 2048")
        self.pages = self.fsize // 2048
        self.blocks = self.pages // 64

    def get_page(self, num):
        self.f.seek(num * 2048)
        return self.f.read(2048)

    def get_spare(self, num):
        raise NotImplementedError("Spare data not supported in bare dump")

    def is_bad_block(self, num):
        return False

class NANDFormatSpare(NANDFormat):
    spare_supported = True
    badblock_supported = True

    def __init__(self, file):
        self.f = open(file, "rb")
        self.f.seek(0, os.SEEK_END)
        self.fsize = self.f.tell()
        self.f.seek(0, os.SEEK_SET)
        self.blocksize = 64
        self.aes_key = b""
        self.hmac_key = b""

        if self.fsize % 2112 != 0:
            raise ValueError("File size not divisible by 2112")
        self.pages = self.fsize // 2112
        self.blocks = self.pages // 64

    def _get_rawpage(self, num):
        self.f.seek(num * 2112)
        page = self.f.read(2112)
        data = page[:2048]
        spare = page[2048:]
        return data, spare

    def get_page(self, num):
        self.f.seek(num * 2112)
        return self.f.read(2048)

    def get_spare(self, num):
        _, spare = self._get_rawpage(num)
        return spare

    def is_bad_block(self, num):
        num = int(num)
        data1, spare1 = self._get_rawpage(num * 64)
        data2, spare2 = self._get_rawpage(num * 64 + 1)
        if (all_zeros(data1) and all_zeros(spare1)) or (all_zeros(data2) and all_zeros(spare2)):
            return False
        b1 = spare1[0] if isinstance(spare1[0], int) else ord(spare1[0])
        b2 = spare2[0] if isinstance(spare2[0], int) else ord(spare2[0])
        return (b1 != 0xff or b2 != 0xff)

class SFFS_entry:
    def __init__(self, fst: bytearray, fat, i, path):
        self.fst = fst
        self.fat = fat
        self.path = path
        buffer = fst[i*0x20:(i+1)*0x20]
        self.name = buffer[0:12].rstrip(b'\x00').decode("utf-8", errors="replace")
        if self.name == "/":
            self.name = ""
        self.mode, self.attr, self.sub, self.sib, \
            self.size, self.uid, self.gid, self.x3 = unpack(">BBHHIIHI", buffer[12:])
        self.chain = None

    def is_file(self):
        return (self.mode & 1) == 1

    def get_cluster_chain(self):
        if self.chain is None:
            self.chain = self.fat.get_cluster_chain(self.sub)
        return self.chain

    def child(self):
        if self.sub == 0xffff or (self.mode & 1) == 1:
            return None
        return SFFS_entry(self.fst, self.fat, self.sub, self.path + self.name + "/")

    def sibling(self):
        if self.sib == 0xffff:
            return None
        return SFFS_entry(self.fst, self.fat, self.sib, self.path)

    def children(self):
        if self.child() is None:
            return []
        retval = [self.child()]
        while retval[-1].sib != 0xffff:
            retval.append(retval[-1].sibling())
        return retval

    def recur_getentry(self, filename):
        if (self.path + self.name) == filename:
            return self
        for c in self.children():
            ret = c.recur_getentry(filename)
            if ret is not None:
                return ret
        return None

class SFFS_fat:
    def __init__(self, buffer):
        self.table = buffer

    def get_cluster_entry(self, num: int):
        return unpack(">H", self.table[num*2:num*2+2])[0]

    def get_cluster_chain(self, num) -> list:
        cluster = 0
        retval = []
        if num < 0 or num >= 0xfff0:
            return retval
        while cluster < 0xFFF0:
            cluster = self.get_cluster_entry(num)
            retval.append(num)
            num = cluster
        return retval

class SFFS:
    def __init__(self, buffer):
        self.data_buffer = buffer
        self.fat = SFFS_fat(buffer[0xc:0x1000c])
        self.fst = buffer[0x1000c:]

    def version(self):
        return unpack(">I", self.data_buffer[0x4:0x8])[0]

def read_superblock(nand, cluster):
    superblock_data = bytearray()
    for offset in range(0, 0x10):
        superblock_data.extend(nand.get_cluster(cluster + offset))
    return superblock_data
