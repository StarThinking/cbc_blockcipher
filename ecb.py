from Crypto.Cipher import AES

import binascii

import sys

BLOCK_SIZE = 16

key = binascii.unhexlify('00112233445566778899aabbccddeeff')

def pad(s):
    pad_len = BLOCK_SIZE - len(s) % BLOCK_SIZE
    if (pad_len == 0):
        pad_len = BLOCK_SIZE
    print('pad_len = ' + str(pad_len))
#    print('s = ' + binascii.hexlify(s))
    return (s + pad_len * chr(pad_len).encode('ascii'))

def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

def encrypt(key, raw):
    raw = pad(raw)
    print('padded = ' + binascii.hexlify(raw))
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(raw)

def decrypt(key, enc):
    cipher = AES.new(key, AES.MODE_ECB)
    dec = cipher.decrypt(enc)
    return unpad(dec)

def getopts(argv):
    opts = {}
    while argv:
        if argv[0][0] == '-':
            opts[argv[0]] = argv[1]
        argv = argv[1:]
    return opts

if __name__ == '__main__':
    myargs = getopts(sys.argv)
    if '-e' in myargs:
        plaintext = binascii.unhexlify(myargs['-e'])
        ciphertext = encrypt(key, plaintext)
        print('Ciphertext: ' + binascii.hexlify(ciphertext))
    elif '-d' in myargs:
        ciphertext = binascii.unhexlify(myargs['-d'])
        plaintext = decrypt(key, ciphertext)
        print('Plaintext: ' + binascii.hexlify(plaintext))
    elif '-s' in myargs:
        plaintext = binascii.a2b_qp(myargs['-s'])
        ciphertext = encrypt(key, plaintext)
        print('Ciphertext: ' +	binascii.hexlify(ciphertext))
    elif '-u' in myargs:
        ciphertext = binascii.unhexlify(myargs['-u'])
        plaintext = decrypt(key, ciphertext)
        print('Plaintext: ' + binascii.b2a_qp(plaintext))
    else:
        print("wrong arguments")
