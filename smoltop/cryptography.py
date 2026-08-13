# Copyright (C) 2026 @malachi196
#
# This file is part of SmolTOP
#
# SmolTOP is a Time-based One Time Pass (TOTP) 2 Factor Authentication (2FA)
# tool that is designed to be very small (smol), and relatively lightweight. This 
# helps make it portable and convenient at a moment's notice, without using too
# many system resources.
#
# SmolTOP is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# SmolTOP is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import hashlib
from time import time
from os import urandom
from callbackprotocols import PRF, HashFunction
import math
import base64
from typing import Literal

#sha-1 blocksize is 64
#sha-1 hash length is 20

def HMAC(key:str|int|bytes, message:str|int|bytes) -> bytes: #hash-based message authentication code
    # convert key and message to bytes if not already:
    if isinstance(key, str): key:bytes = key.encode("utf-8")
    if isinstance(key, int):
        __tmpkey:str = ""
        if str(key).startswith("0x"): __tmpkey:str = f"{key}"[2:]
        else: __tmpkey:str = hex(key)[2:]
        if len(__tmpkey) % 2 != 0:
            __tmpkey = "0" + __tmpkey
        key:bytes = bytes.fromhex(str(__tmpkey))
    if isinstance(message, str): message:bytes = message.encode("utf-8")
    if isinstance(message, int):
        __tmpmsg:str = ""
        if str(message).startswith("0x"): __tmpmsg:str = f"{message}"[2:]
        else: __tmpmsg:str = hex(message)[2:]
        if len(__tmpmsg) % 2 != 0:
            __tmpmsg = "0" + __tmpmsg
        message:bytes=bytes.fromhex(__tmpmsg)
    BLOCKSIZE = 64
    #hmac alg:
    blocksizedkey = _computekeytoblocksize(key, BLOCKSIZE)
    i_pad_key = bytes([a ^ b for a, b in zip(blocksizedkey, bytes(BLOCKSIZE * b"\x36"))]) #inner padded key
    o_pad_key = bytes([a ^ b for a, b in zip(blocksizedkey, bytes(BLOCKSIZE * b"\x5c"))]) #outer padded key
    hashed = _sha1(o_pad_key + _sha1(i_pad_key+message))
    return hashed

def HOTP(key:str|int|bytes, c:int, digits:int = 6) -> str: #HMAC-based once time pass
    bc = c.to_bytes(8, "big") #counter must be an 8 byte value
    hs = HMAC(key, bc)
    snum = _dynamictruncate(hs)
    otp = str((snum % (10**digits)))
    while len(otp) < digits:
        otp = "0"+ otp
    return otp

def TOTP(key:str|int|bytes, timeinterval_s:int=30, digits:int=6, encoding:Literal["none", "base32"]="base32") -> str: #timed one time pass
    if encoding != "none":
        if encoding == "base32":
            key = base64.b32decode(key)
        else:
            raise Exception(f"\"{key}\" isn't a valid/supported encoding!")
    timenow = time()
    counterepoch:int = timenow // timeinterval_s
    return HOTP(key, int(counterepoch), digits=digits)

#password-based key derivation function 2
def PBKDF2(passwd:str|int|bytes, salt:str|int|bytes, c:int, dklen:int, prf:PRF=HMAC, hlen:int=20) -> bytes:
    #hlen is default length for sha-1
    #type conversions (first implemented in the HMAC function above):
    if isinstance(passwd, str): passwd:bytes = passwd.encode("utf-8")
    if isinstance(passwd, int):
        __tmppass:str = ""
        if str(passwd).startswith("0x"): __tmppass:str = f"{passwd}"[2:]
        else: __tmppass:str = hex(passwd)[2:]
        if len(__tmppass) % 2 != 0:
            __tmppass = "0" + __tmppass
        passwd:bytes = bytes.fromhex(__tmppass)
    if isinstance(salt, str): salt:bytes = salt.encode("utf-8")
    if isinstance(salt, int):
        __tmpsalt:str = ""
        if str(salt).startswith("0x"): __tmpsalt:str = f"{salt}"[2:]
        else: __tmpsalt:str = hex(salt)[2:]
        if len(__tmppass) % 2 != 0:
            __tmpsalt = "0" + __tmpsalt
        salt:bytes=bytes.fromhex(__tmpsalt)
    #pbkdf2 alg:
    intervalsnum = math.ceil(dklen/hlen) #number of intervals needed to achieve length of dklen using hlen long blocks
    t = []
    def f(i):
        firstu:bytes = prf(passwd, salt + int(i).to_bytes(4, "big"))
        u = []
        u.append(firstu)
        for interval in range(c-1):
            u.append(prf(passwd, u[interval]))
        result = firstu
        for value in u[1:]:
            result = bytes([a ^ b for a, b in zip(result, value)])
        return result
    for i in range(intervalsnum):
        t.append(f(i+1))
    dk:bytes = t[0]
    for tval in t[1:]:
        dk += tval
    dk = dk[:dklen]
    return dk

def AES256(k, Nc:int=4, Nk:int=4, ):
    pass

def _sha1(data:bytes)->bytes: #sha1 that returns output as bytes
    sha1hash = hashlib.sha1(data)
    return sha1hash.digest()

def _computekeytoblocksize(key:bytes, blocksize:int, hashfunc:HashFunction=_sha1): #generate a blocksized key by resizing key as needed
    if len(key) > blocksize:
        key = hashfunc(key)
    if len(key) < blocksize:
        key = key.ljust(blocksize, b'\x00')
    return key

#returns int instead of bytes because result is 31 bits
def _dynamictruncate(data:bytes)->int: #designed for 20 byte HMAC-SHA1 result
    if len(data) != 20:
        raise ValueError("data is not 20 bytes!")
    obyte:int = data[19]
    offset = obyte & 0x0f #lower order 4 bits
    p = ""
    for i in range(4):
        patoffset = str(hex(data[offset+(i)])[2:])
        if len(patoffset) % 2 != 0:
            patoffset = "0" + patoffset
        p += patoffset
    ptrunc = int(p, 16) & 0x7fffffff #clear 32nd bit reducing it to 31 bit
    return ptrunc
