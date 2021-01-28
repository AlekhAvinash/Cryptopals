#!/usr/bin/python3

from Cryptopals import xor, get_english_score

def solve_xor(cip):
	scr = [get_english_score(xor(cip, bytes([i]))) for i in range(255)]
	return xor(cip,bytes([scr.index(max(scr))]))

if __name__ == '__main__':
	file_strings = open('4.txt', 'r').read().split('\n')
	xored_list = [solve_xor(bytes.fromhex(i)) for i in file_strings]
	
	scr = []
	for i in xored_list:
		try:
			scr += [get_english_score(i)]
		except:
			pass
	assert xored_list[scr.index(max(scr))] == b'Now that the party is jumping\n'