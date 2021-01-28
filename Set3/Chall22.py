#!/usr/bin/python3

from Cryptopals import mersenne
from random import randint
from time import time

def gen_rand_num() -> int:
	seed = int(time())+randint(40, 1000)
	return mersenne(seed).next(), seed

def brute(rand_num: int) -> int:
	now = int(time())
	for i in range(1100):
		if(rand_num == mersenne(now+i).next()):
			return now+i
	if i==1100:
		return -1

if __name__ == '__main__':
	rand_num, seed = gen_rand_num()
	assert seed == brute(rand_num)