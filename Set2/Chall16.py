#!/usr/bin/python3

from os import urandom
from urllib.parse import quote
from Cryptopals import cbc_encrypt, cbc_decrypt

KEY = urandom(16)
IV = urandom(16)
PRE = b"comment1=cooking%20MCs;userdata="
POST = b";comment2=%20like%20a%20pound%20of%20bacon"
INP = b';admin=true;'

encrypt = lambda pt: cbc_encrypt(quote(PRE+pt+POST).encode(), KEY, IV)
decrypt = lambda ct: INP in cbc_decrypt(ct, KEY)

class bitflip:
	def __init__(self, ct: bytes, pt: bytes):
		self.bts2arr = lambda cip: [i for i in cip]
		self.arr2bts = lambda cip: b''.join([bytes([i]) for i in cip])
		self.ct = self.bts2arr(ct)
		self.pt = self.bts2arr(pt)

	def replace(self, rep: int, loc: int) -> None:
		self.ct[loc] ^= (self.pt[loc]^rep)

def attack(obj: object, inp: bytes, loc: int) -> bytes:
	for i,j in enumerate(inp):
		obj.replace(j, loc+i)
	return obj.arr2bts(obj.ct)

if __name__ == '__main__':
	qt = quote(PRE+INP+POST)
	atk = attack(bitflip(encrypt(INP), qt.encode()), INP, 0)
	assert decrypt(atk)