#!/usr/bin/python3
from Cryptopals import xor

if __name__ == '__main__':
	a = '1c0111001f010100061a024b53535009181c'
	b = '686974207468652062756c6c277320657965'
	assert xor(bytes.fromhex(a), bytes.fromhex(b)).hex() == '746865206b696420646f6e277420706c6179'