#!/usr/bin/python3

from Crypto.Cipher import AES
from base64 import b64decode
from Cryptopals import split_blocks, xor, pkcs7_pad, pkcs7_unpad

KEY = b"YELLOW SUBMARINE"
IV = b"\x00"*16

class CBC:
	def __init__(self, KEY, IV):
		self.KEY = KEY
		self.IV = IV
		self.pt = []
		self.ct = []

	def encrypt(self, pt: bytes) -> bytes:
		blks = [self.IV]+split_blocks(pkcs7_pad(pt, 16), 16)
		prev = blks[0]
		for i in blks[1:]:
			self.ct += [self.encrypt_ecb(xor(prev,i))]
			prev = self.ct[-1]
		return b''.join(self.ct)

	def encrypt_ecb(self, pt: bytes) -> bytes:
		enc = AES.new(self.KEY, AES.MODE_ECB)
		return enc.encrypt(pt)

	def decrypt(self, ct: bytes) -> bytes:
		blks = ([self.IV]+split_blocks(ct, 16))[::-1]
		prev = self.decrypt_ecb(blks[0])
		for i in blks[1:]:
			self.pt += [xor(i,prev)]
			prev = self.decrypt_ecb(i)
		return pkcs7_unpad(b''.join(self.pt[::-1]))

	def decrypt_ecb(self, ct: bytes) -> bytes:
		enc = AES.new(self.KEY, AES.MODE_ECB)
		return enc.decrypt(ct)

if __name__ == '__main__':
	ct = b64decode(open('10.txt','r').read())
	assert CBC(KEY, IV).encrypt(CBC(KEY, IV).decrypt(ct)) == ct