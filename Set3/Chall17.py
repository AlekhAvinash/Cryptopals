#!/usr/bin/python3
from base64 import b64decode
from Cryptopals import cbc_encrypt, cbc_decrypt, bitflip, pkcs7_unpad
from os import urandom
from random import choice

KEY = urandom(16)
IV = urandom(16)
lis = list(map(b64decode, open('17.txt', 'r').read().split('\n')))
enc = lambda : cbc_encrypt(choice(lis), KEY, IV)

def dec(ct: bytes):
	try:
		cbc_decrypt(ct, KEY)
		return True
	except AssertionError:
		return False

class padding_oracle_atk:
	def __init__(self, ct):
		self.ct = ct+b'\x00'*16
		self.pt = [0]*16
		
	def find_bytes(self, st: int, rep: int) -> bytes:
		for j in range(256):
			self.pt.insert(0, j)
			obj = bitflip(self.ct[:-st])
			if dec(obj.replace(self.pt[:-st],[rep]*rep,-(16+rep))) and j!=rep:
				break
			self.pt.pop(0)

	def padding_atk(self) -> bytes:
		self.find_bytes(16, 1)
		[self.pt.insert(0, self.pt[0]) for i in range(self.pt[0]-1)]
		for i in range(self.pt[-17], len(self.ct)-32):
			self.find_bytes((1+i//16)*16, (i%16)+1)
		return pkcs7_unpad(b''.join([bytes([i]) for i in self.pt])[:-16])

if __name__ == '__main__':
	assert padding_oracle_atk(enc()).padding_atk() in lis