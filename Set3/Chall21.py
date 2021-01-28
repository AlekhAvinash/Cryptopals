#!/usr/bin/python3

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

if __name__ == '__main__':
	rand = mersenne(1234)
	lis = []
	for i in range(1000):
		x = rand.next()
		if(x not in lis):
			lis += [x]
		else:
			raise Exception("Error!!")