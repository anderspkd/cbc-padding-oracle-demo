#!/usr/bin/env python

from os import urandom as rand
from requests import get as _get
from binascii import unhexlify

base_url = 'http://127.0.0.1:5000%s'
block_size = 16  # AES block size in bytes


def get(url):
    return _get(base_url % url)


def get_encrypted_flag():
    return get('/encrypted_flag').content.strip()


def padding_valid(r, y):
    # Query the oracle to see if the padding is valid

    c = r + y

    url = '/decrypt?'
    url += bytes(c).hex()

    r = get(url).content.strip()
    if b'OK' == r:
        return True
    elif b'Bad padding' == r:
        return False
    else:
        print('[!] weird server response:', r)
        exit(0)
        # return False


def decrypt_block(y, block_num):

    y = [c for c in y]
    # rs = [c for c in rand(block_size)]
    rs = [0x00] * block_size

    i = block_size - 1
    found = False
    while i >= 0:
        pb = block_size - i  # padding byte

        print('[block #{}] {}'.format(block_num, '.'*pb), end='\r')

        rh = rs[:i]
        rt = [c ^ pb for c in rs[i + 1:]]

        for j in range(256):
            r = rh + [j] + rt

            if padding_valid(r, y):
                rs[i] = pb ^ j
                found = True
                break

        if found:
            i -= 1
        else:
            print('[!] nothing found for pb={}, rs[{}]={}'.format(pb, i, rs[i]))
            i -= 1

        found = False

    print()
    return rs


if __name__ == '__main__':
    # enc_flag = IV || C
    enc_flag = unhexlify(get_encrypted_flag())

    # Not /really/ necessary
    iv = enc_flag[:16]
    enc_flag = enc_flag[16:]

    blocks = []
    for i in range(0, len(enc_flag), block_size):
        blocks = [enc_flag[i:i+block_size]] + blocks

    print('[*] {} blocks'.format(len(blocks)))

    msg = ''
    i = 0
    while i < len(blocks) - 1:
        d = decrypt_block(blocks[i], len(blocks) - i)
        if d is None:
            continue
        else:
            msg = ''.join(chr(c1 ^ c2) for c1, c2 in zip(d, blocks[i+1])) + msg
            i += 1

    d = decrypt_block(blocks[-1], 1)
    msg = ''.join(chr(c1 ^ c2) for c1, c2 in zip(d, iv)) + msg

    flag = msg.strip()

    # test the flag we found
    if get('/test_flag?' + flag).content.strip() == b'Yay':
        print('Correct flag:', flag)
    else:
        print('Incorrect flag:', flag)
