from flask import Flask, request, redirect, Response
from Crypto.Cipher import AES
from os import urandom as rand
import logging
log = logging.getLogger('werkzueg')
log.setLevel(logging.ERROR)

app = Flask(__name__)

# Typical CTF style flag
flag = 'flag{%s}' % rand(32).encode('hex')
key = rand(32)


# adds PKCS#7 padding
def pad(m):
    l = 16 - len(m) % 16
    return m + (chr(l) * l)


# removes PKCS#7 padding. Returns `None' if padding is wrong.
def unpad(m):
    l = ord(m[-1])
    for c in m[-l:]:
        if ord(c) != l:
            return
    if 0 < l <= 16:
        return m[:-l]


@app.route('/encrypted_flag')
def get_encrypted_flag():
    iv = rand(16)  # random IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    padded_flag = pad(flag)
    c = cipher.encrypt(padded_flag)

    print 'Flag: %r' % padded_flag

    pl = '%s%s' % (iv, c)

    return pl.encode('hex') + '\n'


@app.route('/decrypt')
def decrypt_flag():
    try:
        _c = request.args.keys()[0].decode('hex')
        iv = _c[:16]
        c = _c[16:]
        assert len(iv) == 16, 'len(iv)=%s, hex(iv)=%s' % (len(iv), iv.encode('hex'))
    except:
        return 'Nothing to decrypt\n'

    if len(c) % 16 != 0:
        return 'Ciphertext not a multiple of block length\n'

    cipher = AES.new(key, AES.MODE_CBC, iv)

    p = unpad(cipher.decrypt(c))

    if p is not None:
        return 'OK\n'
    else:
        return 'Bad padding\n'


@app.route('/test_encryption')
def test_encryption():
    encrypted = request.args['e'].decode('hex')
    decrypted = request.args['d']

    iv = encrypted[:16]
    c = encrypted[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    p = unpad(cipher.decrypt(c))

    if p == decrypted:
        return 'Yay\n'
    else:
        return 'Boo\n'


@app.route('/test_flag')
def test_flag():
    flag_cand = request.args.keys()[0]

    if flag == flag_cand:
        return 'Yay\n'
    else:
        return 'Boo\n'

if __name__ == '__main__':
    app.run()
