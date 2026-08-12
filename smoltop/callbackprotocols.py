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