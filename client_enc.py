#!/usr/bin/env python

from os import urandom as rand
from client_dec import decrypt_block, block_size, get


# adds PKCS#7 padding
def pad(m):
    l = 16 - len(m) % 16
    return m + (chr(l) * l)


# Use the padding oracle to encrypt a block `b'
def encrypt_block(t, c, i):
    t = [ord(c) for c in t]
    a = decrypt_block(c, i)
    b = ''.join(chr(c1 ^ c2) for c1, c2 in zip(a, t))
    return bytes([ord(i) for i in b])


if __name__ == '__main__':
    import sys

    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        print(f'Usage: {sys.argv[0]} target_plaintext')
        exit(0)

    padded_target = pad(target)  # add padding

    blocks = []
    j = 0
    for i in range(0, len(padded_target), block_size):
        blocks = [(j, padded_target[i:i+block_size])] + blocks
        j += 1

    c = rand(block_size)
    encrypted = [c]
    for i, b in blocks:
        c = encrypt_block(b, c, i)
        encrypted = [c] + encrypted

    encrypted = ''.join(b.hex() for b in encrypted)
    print(get(f'/test_encryption?d={target}&e={encrypted}').content)
