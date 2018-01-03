from flask import Flask
from Crypto.Cipher import AES
from os import urandom as rand
from binascii import unhexlify

app = Flask(__name__)
flag = 'flag{' + rand(32).hex() + '}'
key = rand(32)  # AES key


# Creates an AES cipher object
def aes(iv):
    return AES.new(key, AES.MODE_CBC, iv)


# apply PKCS#7 padding to m
def pad(m):
    ln = 16 - len(m) % 16
    return m + (chr(ln) * ln)


# remove PKCS#7 padding. Exposes a padding oracle
def unpad(m):
    ln = m[-1]
    for c in m[-ln:]:
        if c != ln:
            return
    if 0 < ln <= 16:
        return m[:-ln]


# returns the flag, encrypted under the key and a random IV
@app.route('/flag')
def get_flag():
    iv = rand(16)
    c = aes(iv).encrypt(pad(flag))

    return f'{iv.hex()}{c.hex()}'


def decrypt(c):
    c = unhexlify(c)

    iv = c[:16]
    c = c[16:]

    if len(c) % 16:
        return

    return unpad(aes(iv).decrypt(c))


# attempts to decrypt
@app.route('/decrypt/<c>')
def decrypt_silent(c):
    p = decrypt(c)

    if p is None:
        return 'bad padding'

    return 'ok'


@app.route('/decrypt_reveal/<c>')
def decrypt_loud(c):
    return decrypt(c)
