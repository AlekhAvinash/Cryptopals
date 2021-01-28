#!/usr/bin/python3
import re
from os import urandom
from Cryptopals import ecb_encrypt, ecb_decrypt, pkcs7_pad, pkcs7_unpad

KEY = urandom(16)

def bytes_2_dict(txt: bytes) -> dict:
    ret = {}
    for i in txt.split(b'&'):
        key, value = i.split(b'=')
        ret[key] = value
    return ret

def dict_2_bytes(obj: dict) -> bytes:
    return b'&'.join([i[0]+b'='+i[1] for i in obj.items()])

rep = re.compile('([&=])')
def profile_for(email: bytes) -> bytes:
    ret = {}
    ret[b'email'] = rep.sub(':', email.decode()).encode()
    ret[b'uid'] = b'10'
    ret[b'role'] = b'user'
    return ecb_encrypt(dict_2_bytes(ret), KEY)

def attack() -> bytes:
    ct = profile_for(b'attac@ker.com')
    atk = ct[:-16] + profile_for(b'a'*10+pkcs7_pad(b'admin', 16))[16:32]
    return bytes_2_dict(ecb_decrypt(atk, KEY))

if __name__ == "__main__":
    assert attack()[b'role']==b'admin'