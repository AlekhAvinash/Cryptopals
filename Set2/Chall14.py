#!/usr/bin/python3

from os import urandom
from random import randint
from base64 import b64decode
from string import printable
from Cryptopals import ecb_encrypt, split_blocks

KEY = urandom(16)
unknown = b64decode(open('12.txt','r').read())
rand_prefix = urandom(randint(1,16))

class BAAT_attack():
	def __init__(self, oracle):
		self.oracle = oracle
		self.oracle_blks = lambda pt : split_blocks(oracle(pt))
		self.unknown = b''

	def find_len(self) -> int:
		prev = None
		for i in range(16):
			ctr = len(self.oracle_blks(b'\x00'*i))
			if(prev == None):
				prev = ctr
			if(ctr != prev):
				return prev*16 - i
		return -1

	def find_len_prefix(self) -> int:
		prev = self.oracle_blks(b'\x00'*0)[:3]
		curr = self.oracle_blks(b'\x00'*1)[:3]
		no_blks = sum([1 if(i==j) else 0 for i, j in zip(prev, curr)])

		prev = self.oracle_blks(b'\x00'*16)[no_blks]
		for i in range(15,-1,-1):
			ctr = self.oracle_blks(b'\x00'*i)[no_blks]
			if(ctr != prev):
				return no_blks*16 + 15-i
		return -1

	def find_last_byte(self, pt: bytes, blk: int) -> bytes:
		ct = self.oracle_blks(pt)[blk]
		for i in printable:
			if self.oracle_blks(pt+self.unknown+i.encode())[blk] == ct:
				return i.encode()
		return b''

	def find_unkwn(self) -> bytes:
		key_len = self.find_len()
		prx_len = self.find_len_prefix()
		pad = b'\x00'*(16 - prx_len%16)
		for i in range(key_len - prx_len):
			inp = b'\x00'*(15-i%16)
			lbyte = self.find_last_byte(pad + inp, (prx_len//16) + 1 + (i//16))
			if(lbyte!=b''):
				self.unknown += lbyte
			else:
				raise Exception('Did not find element!!')
		return self.unknown

if __name__ == '__main__':
	ecb = lambda pt: ecb_encrypt(rand_prefix+pt+unknown, KEY)
	assert BAAT_attack(ecb).find_unkwn() == unknown