#!/usr/bin/python3

from Cryptopals import pkcs7_pad, pkcs7_unpad
if __name__ == '__main__':
	assert b'abc' == pkcs7_unpad(pkcs7_pad(b'abc'))