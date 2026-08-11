from typing import Protocol, overload

class PRF(Protocol): #for type checking
    """Psuedo Random Function (e.g. HMAC)"""
    def __call__(self,
        key:str|int|bytes,
        message:str|int|bytes
        ) -> bytes:
        ...

class HashFunction(Protocol):
    """Hash Function (e.g. MD5, SHA-1, SHA-256, etc.)"""
    def __call__(self,
        *args:bytes,
        **kwargs:bytes
        ) -> bytes:
        ...