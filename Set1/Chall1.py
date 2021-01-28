#!/usr/bin/python3
from base64 import b64encode
hex_base64 = lambda str: b64encode(bytes.fromhex(str))
if __name__ == '__main__':
	inp = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
	assert hex_base64(inp) == b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'