#!/usr/bin/python3

from base64 import b64decode
from os import urandom
from Cryptopals import split_blocks, ctr, repeated_xor, xor
nonce = lambda n: b'\x00'*16
pt = list(map(b64decode, open('20.txt','r').read().split('\n')))

def ctr_break():
	key = urandom(16)
	ct = [ctr(i, key, nonce) for i in pt]
	x = repeated_xor(b''.join([j for i in ct for j in split_blocks(i) if(len(j)==16)]))
	key = split_blocks(x.find_key(x.find_key_size()))[0]
	return [xor(i, key) for i in ct] == pt

if __name__ == '__main__':
	assert any([ctr_break() for i in range(2)])