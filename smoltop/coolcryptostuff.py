#backendcryptography file

import hashlib

#sha-1 blocksize is 64

def HMAC(key:str|int|bytes, message:str|int|bytes) -> bytes: #hash-based message authentication code
    # convert key and message to bytes if not already:
    if isinstance(key, str): key:bytes = key.encode("utf-8")
    if isinstance(key, int):
        __tmpkey:str = ""
        if str(key).startswith("0x"): __tmpkey:str = f"{key}"[2:]
        else: __tmpkey:str = f"{hex(key)}"[2:]
        key:bytes = bytes.fromhex(__tmpkey)
    if isinstance(message, str): message:bytes = message.encode("utf-8")
    if isinstance(message, int):
        __tmpmsg:str = ""
        if str(message).startswith("0x"): __tmpmsg:str = f"{message}"[2:]
        else: __tmpmsg:str = f"{hex(message)}"[2:]
        message:bytes=bytes.fromhex(__tmpmsg)
    BLOCKSIZE = 64
    #hmac alg:
    blocksizedkey = _computekeytoblocksize(key, BLOCKSIZE)
    i_pad_key = bytes([a ^ b for a, b in zip(blocksizedkey, bytes(BLOCKSIZE * b"\x36"))]) #inner padded key
    o_pad_key = bytes([a ^ b for a, b in zip(blocksizedkey, bytes(BLOCKSIZE * b"\x5c"))]) #outer padded key
    hashed = _sha1(o_pad_key + _sha1(i_pad_key+message))
    return hashed

def _sha1(data:bytes)->bytes: #sha1 that returns output as bytes
    sha1hash = hashlib.sha1(data)
    return sha1hash.digest()

def _computekeytoblocksize(key:bytes, blocksize:int): #generate a blocksized key by resizing key as needed
    if len(key) > blocksize:
        key = _sha1(key)
    if len(key) < blocksize:
        key = key.ljust(blocksize, b'\x00')
    return key
