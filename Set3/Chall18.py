#!/usr/bin/python3

from base64 import b64decode
from os import urandom
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Cryptopals import split_blocks, xor, ecb_encrypt

KEY = b"YELLOW SUBMARINE"
def ctr(ct: bytes, key: bytes, counter) -> bytes:
	ret = b''
	for j,i in enumerate(split_blocks(ct)):
		ret += xor(ecb_encrypt(counter(j),key,False),i)
	return ret[:len(ct)]

def ctr2(ct: bytes, key: bytes, ctr: object) -> bytes:
	enc = AES.new(KEY, AES.MODE_CTR, counter=ctr)
	return enc.decrypt(ct)

cip = b64decode(b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
if __name__ == '__main__':
	counter = lambda n: b'\x00'*8+(n).to_bytes(8, byteorder='little')
	counter2 = Counter.new(64, initial_value=0, prefix=b'\x00'*8, little_endian=True)
	assert ctr(cip,KEY, counter) == ctr2(cip, KEY, counter2)