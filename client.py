#!/usr/bin/env python

from requests import get as _GET
from binascii import unhexlify
import argparse

p = argparse.ArgumentParser()
p.add_argument('url', help='server url')
p.add_argument('-e', metavar='plaintext', dest='ptxt',
               help='text to encrypt')
p.add_argument('-b', metavar='lastblock', dest='last_block',
               help='last block of new encryption')
args = p.parse_args()

block_size = 16
should_encrypt = args.ptxt is not None


# add PKCS#7 padding. Needed when we encrypt via. the padding oracle
def pad(m):
    ln = 16 - len(m) % 16
    return m + (chr(ln) * ln)


def get(path):
    return _GET(f'http://{args.url}{path}').content


def valid_padding(c):
    r = get(f'/decrypt/{c.hex()}')

    if b'ok' == r:
        return True
    elif b'bad padding' == r:
        return False
    else:
        raise Exception(r)


def decrypt_block(y, block_num):
    y = list(y)
    rs = [0] * block_size

    i = block_size - 1
    found = False
    while i >= 0:
        pb = block_size - i  # current padding byte
        print(f'[block #{block_num}] {"."*pb}', end='\r')
        rh = rs[:i]
        rt = [c ^ pb for c in rs[i + 1:]]

        for j in range(256):
            r = rh + [j] + rt
            if valid_padding(bytes(r + y)):
                rs[i] = pb ^ j
                found = True
                break
        i -= 1

        if not found:
            print(f'[!] nothing found for pb={pb}, rs[{i}]={rs[i]}')

        found = False

    print()
    return rs


def encrypt_block(t, c, i):
    t = [ord(c) for c in t]
    a = decrypt_block(c, i)
    b = ''.join(chr(c1 ^ c2) for c1, c2 in zip(a, t))
    return bytes([ord(i) for i in b])


def decrypt():
    cflag = unhexlify(get('/flag'))

    iv = cflag[:block_size]
    cflag = cflag[block_size:]

    blocks = []
    for i in range(0, len(cflag), block_size):
        blocks = [cflag[i:i+block_size]] + blocks

    print(f'[ ] {len(blocks)} blocks')

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

    ptxt = msg.strip()

    print(f'[ ] plaintext={ptxt}')


def encrypt():
    ptxt = pad(args.ptxt)

    blocks = []
    j = 0
    for i in range(0, len(ptxt), block_size):
        blocks = [(j, ptxt[i:i + block_size])] + blocks
        j += 1

    # default to all 0 block
    c = bytes(args.last_block, 'ascii') or bytes(block_size)
    assert len(c) == block_size, 'last block must have length 16'

    ctxt = [c]
    for i, b in blocks:
        c = encrypt_block(b, c, i)
        ctxt = [c] + ctxt

    ctxt = ''.join(b.hex() for b in ctxt)

    print(f'[ ] ciphertext={ctxt}')
    ptxt2 = get(f'/decrypt_reveal/{ctxt}')
    print(f'[ ] server_decrypt(ciphertext)={ptxt2}')


if __name__ == '__main__':
    if should_encrypt:
        encrypt()
    else:
        decrypt()
