#!/usr/bin/python3
from os import urandom
from base64 import b64decode
from string import printable
from Cryptopals import split_blocks, ecb_encrypt

KEY = urandom(16)
unknown = b64decode(open('12.txt','r').read())

class BAAT_attack(object):
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

	def is_ECB(self) -> int:
		ct = self.oracle(b'\x00'*32)
		blks = split_blocks(ct)
		if(blks[0] == blks[1]):
			return True
		return False

	def find_last_byte(self, pt: bytes, blk: int) -> bytes:
		ct = self.oracle_blks(pt)[blk]
		for i in printable:
			if self.oracle_blks(pt+self.unknown+i.encode())[blk] == ct:
				return i.encode()
		return b''

	def find_unkwn(self) -> bytes:
		key_len = self.find_len()
		assert self.is_ECB()
		for i in range(key_len):
			inp = b'\x00'*(15-i%16)
			lbyte = self.find_last_byte(inp, i//16)
			if(lbyte!=b''):
				self.unknown += lbyte
			else:
				raise Exception('Did not find element!!')
		return self.unknown

if __name__ == '__main__':
	ecb = lambda pt: ecb_encrypt(pt+unknown, KEY)
	assert BAAT_attack(ecb).find_unkwn() == unknown