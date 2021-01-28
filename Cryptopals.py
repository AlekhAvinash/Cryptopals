#!/usr/bin/python3

from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes

xor = lambda msg, key: b''.join([bytes([byte ^ key[i%len(key)]]) for i,byte in enumerate(msg)])

freq = {'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253, 'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094, 'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025, 'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929, 'q': .00095, 'r': .05987, 's': .06327, 't': .09056, 'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150, 'y': .01974, 'z': .00074, ' ': .13000}
get_english_score = lambda input_bytes: sum([freq.get(chr(byte), 0) for byte in input_bytes.lower()])

hamming_dist = lambda x, y: sum([int(i) for i in bin(bytes_to_long(xor(x,y)))[2:]])

def split_blocks(cip: bytes, key = 16) -> list: 
	return [cip[i:i+key] for i in range(0,len(cip),key)]

def solve_xor(cip: bytes) -> bytes:
	scr = [get_english_score(xor(cip, bytes([i]))) for i in range(255)]
	return bytes([scr.index(max(scr))])

def pkcs7_pad(pt: bytes, sz = 16) -> bytes:
	pad = (sz-len(pt)%sz)
	return pt+bytes([pad])*pad

def pkcs7_unpad(pt: bytes) -> bytes:
	assert all([pt[-1] == i for i in pt[-pt[-1]:]]) and pt[-1] in range(1,17), "Incorrect Padding"
	return pt[:-pt[-1]]

def ecb_encrypt(pt: bytes, key: bytes, padding = True) -> bytes:
	enc = AES.new(key, AES.MODE_ECB)
	if not padding:
		return enc.encrypt(pt)
	return enc.encrypt(pkcs7_pad(pt))

def ecb_decrypt(ct: bytes, key: bytes) -> bytes:
	enc = AES.new(key, AES.MODE_ECB)
	return pkcs7_unpad(enc.decrypt(ct))

def cbc_encrypt(pt: bytes, key: bytes, iv: bytes) -> bytes:
	enc = AES.new(key, AES.MODE_CBC, iv=iv)
	return iv+enc.encrypt(pkcs7_pad(pt))

def cbc_decrypt(ct: bytes, key: bytes) -> bytes:
	enc = AES.new(key, AES.MODE_CBC, ct[:16])
	return pkcs7_unpad(enc.decrypt(ct[16:]))

def ctr(ct: bytes, key: bytes, counter) -> bytes:
	ret = b''
	for j,i in enumerate(split_blocks(ct)):
		ret += xor(ecb_encrypt(counter(j),key,False),i)
	return ret[:len(ct)]

class repeated_xor:
	def __init__(self, ct: bytes, sz = range(2, 41)):
		self.func_blocks = lambda blks, fnc: [fnc(blks[i],blks[i-1]) for i in range(1,len(blks))]
		self.byte_split_blocks = lambda blocks, key:b"".join([bytes([blk[key]]) for blk in blocks])
		self.ct = ct
		self.KEYSIZE = sz

	def find_key_size(self) -> bytes:
		normalized_val_list = []
		for key_size in self.KEYSIZE:
			blocks = split_blocks(self.ct, key_size)[:-1]
			avg_ham_dist = sum(self.func_blocks(blocks, hamming_dist))/(len(blocks)-1)
			normalized_val_list += [avg_ham_dist/key_size]
		return normalized_val_list.index(min(normalized_val_list))+self.KEYSIZE[0]

	def find_key(self, key_size: bytes) -> bytes:
		blocks = split_blocks(self.ct, key_size)[:-1]
		return b"".join([solve_xor(self.byte_split_blocks(blocks, i)) for i in range(key_size)])

bts2arr = lambda cip: [i for i in cip]
arr2bts = lambda cip: b''.join([bytes([i]) for i in cip])
class bitflip:
	def __init__(self, ct: bytes):
		self.ct = bts2arr(ct)

	def replace(self, pt: list, rep: list, loc: int) -> bytes:
		for i in range(len(pt)):
			self.ct[loc+i] ^= (pt[i]^rep[i])
		return arr2bts(self.ct)

class mersenne:
	def __init__(self, seed: int, w = 32, n = 624, m = 397, r = 31):
		self.w = (1<<w)-1
		self.n = n
		self.m = m
		self.MT = [0]*self.n
		self.index = self.n+1
		self.seed_mt(seed)
		self.lower_mask = (1<<r)-1
		self.upper_mask = self.wbits(1<<r)

	def wbits(self, n: int) -> int:
		dist = len(bin(n)) - len(bin(self.w))
		ret = self.w&n
		if(dist<0):
			ret |= ((1<<(-1*dist))-1)<<(len(bin(ret))-2)
		return ret

	def seed_mt(self, seed):
		self.index = self.n
		self.MT[0] = seed
		f = 1812433253
		for i in range(1, self.index-1):
			self.MT[i] = self.wbits(f*(self.MT[i-1]^(self.MT[i-1]>>(self.w-2)))+i)

	def next(self):
		if(self.index>=self.n):
			if(self.index>self.n):
				raise Exception("Generator Not Seeded!!")
			self.twist()

		u, d = 29, int('555555555555555516', 16)
		s, b = 17, int('71D67FFFEDA6000016', 16)
		t, c = 37, int('FFF7EEE00000000016', 16)
		l = 18

		y = self.MT[self.index]
		y ^= ((y>>u)&d)
		y ^= ((y>>s)&b)
		y ^= ((y>>t)&c)
		y ^= (y>>l)

		self.index += 1
		return self.wbits(y)

	def twist(self):
		a = int('B5026F5AA96619E916', 16)
		for i in range(self.n-1):
			x = (self.MT[i]&self.upper_mask)+(self.MT[i+1%self.n]&self.lower_mask)
			xA = x>>1
			if(x%2):
				xA ^= a
			self.MT[i] = self.MT[(i+self.m)%self.n]^xA
		self.index = 0
