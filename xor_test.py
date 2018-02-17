from Crypto.Cipher import AES
from operator import xor

import binascii
import sys

BLOCK_SIZE = 16

key = binascii.unhexlify('00112233445566778899aabbccddeeff') # binary
iv = 0x00000000000000000000000000000000 # hex
#iv = binascii.unhexlify('0123456789abcdef0123456789abcdef') # binary


if __name__ == '__main__':
    plaintext = binascii.unhexlify('12ba')
    print binascii.hexlify(plaintext)
    xored = int(binascii.hexlify(plaintext), base=16) ^ int('0000', base=16)
    xored = hex(xored)[2:].zfill(16)
    cipher = AES.new(key, AES.MODE_ECB)
    cipher.encrypt(xored)
    #cipher.encrypt(str(x).zfill(16))
