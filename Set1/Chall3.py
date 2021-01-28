#!/usr/bin/python3

from Cryptopals import xor, get_english_score

def solve_xor(cip: bytes) -> bytes:
	scr = [get_english_score(xor(cip, bytes([i]))) for i in range(255)]
	return bytes([scr.index(max(scr))])

if __name__ == '__main__':
	cip = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
	assert xor(cip,solve_xor(cip)) == b"Cooking MC's like a pound of bacon"