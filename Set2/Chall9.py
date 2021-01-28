#!/usr/bin/python3

from Cryptopals import pkcs7_pad
if __name__ == '__main__':
	assert pkcs7_pad(b"YELLOW SUBMARINE", 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04'