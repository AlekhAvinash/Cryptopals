#!/usr/bin/python3

from Cryptopals import mersenne, xor
from random import randint

def cipher(pt, seed):
	prng = mersenne(seed)
	key = b''.join([bytes([(prng.next())%1<<8]) for _ in range(len(pt))])
	print(key)
	return xor(pt, key)

def exploit_seed(pt, ct):
	for i in range(2, 1<<16):
		print(cipher(ct, i), pt)
		if(cipher(ct, i) == pt):
			return i
	return -1

if __name__ == '__main__':
	pt = b'a'*14
	seed = randint(2, 1<<16)
	ct = cipher(pt, seed)
	assert pt == cipher(ct, seed)
	print(seed ,exploit_seed(pt, ct))

	