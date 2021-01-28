#!/usr/bin/python3

from os import urandom
from random import randint
from Crypto.Cipher import AES
from Cryptopals import split_blocks, pkcs7_pad

add = lambda txt, byte: byte*randint(5, 10) + txt + byte*randint(5, 10)
def ecb(pt: bytes, key: bytes) -> bytes:
	enc = AES.new(key, AES.MODE_ECB)
	return enc.encrypt(pt)

def cbc(pt: bytes, key: bytes, iv: bytes) -> bytes:
	enc = AES.new(key, AES.MODE_CBC, iv=iv)
	return enc.encrypt(pt)

def black_box(pt: bytes) -> bytes:
	pt = pkcs7_pad(add(pt, b'\x00'), 16)
	if(randint(0,1)):
		return ecb(pt, urandom(16)), 1
	return cbc(pt, urandom(16), urandom(16)), 0

def detective(ct: bytes) -> int:
	blks = split_blocks(ct)
	if(blks[0] == blks[1]):
		return 1
	return 0

if __name__ == '__main__':
	ret = black_box(b'\x00'*32)
	assert detective(ret[0]) == ret[1]