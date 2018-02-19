from Crypto.Cipher import AES

import binascii

import sys

BLOCK_SIZE = 16
hexchar_in_block = 32

key = binascii.unhexlify('00112233445566778899aabbccddeeff')
iv = '10000200000000100000000000a00000'

def pad(s):
    pad_len = BLOCK_SIZE - len(s) % BLOCK_SIZE
    if (pad_len == 0):
        pad_len = BLOCK_SIZE
    print('pad_len (bytes) = ' + str(pad_len))
#    print('s = ' + binascii.hexlify(s))
    return (s + pad_len * chr(pad_len).encode('ascii'))

def unpad(s):
    #print 's = ' + binascii.hexlify(s)
    #print 'len(s) = ' + str(len(s))
    #print 'ord = ' + str(ord(s[len(s) - 1:]))
    s = s[len(s) - 16:] 
    last_byte = s[len(s) - 1:]
    pad_bytes = ord(last_byte)
    #print 'pad_bytes = ' + str(pad_bytes)
    if (pad_bytes > 16 or pad_bytes <= 0):
        return 'no'
    unpad_bytes = BLOCK_SIZE - pad_bytes
    unpad = s[:-pad_bytes]
    #print 'unpad_bytes = ' + str(unpad_bytes)
    paddings = s[unpad_bytes:]
    byte_index = 0
    #print 'unpad = ' + unpad
    #print 'pad = ' + binascii.hexlify(paddings)
    #print 'last_byte =' + binascii.hexlify(last_byte)
    #print 'pad_bytes = ' + str(pad_bytes)
    while byte_index < pad_bytes:
        p = binascii.hexlify(paddings[byte_index])
        if (p != binascii.hexlify(last_byte)):
            #print 'no becase:'
            #print 'p = ' + p
            #print 'last_byte = ' + binascii.hexlify(last_byte)
            return 'no'
        byte_index += 1
#    print 'ok padding = ' + binascii.hexlify(paddings)
    return 'yes'

def verify(enc):
    enc = binascii.unhexlify(enc)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_hexchar = binascii.hexlify(enc)
    block_num = len(ciphertext_hexchar) / hexchar_in_block
    block_index = 0
    plaintext_hexchar = ""
    prev_hexchar = ""

    while block_index < block_num:
        start = block_index * hexchar_in_block
        end = start + hexchar_in_block
        cblock_hexchar = ciphertext_hexchar[start:end]
        xor1_hexchar = binascii.hexlify(cipher.decrypt(binascii.unhexlify(cblock_hexchar)))
        xor1 = int(xor1_hexchar, base=16)
        
        if (block_index == 0):
            xor2 = int(iv, base=16)
        else:
            xor2 = int(prev_hexchar, base=16)
        
        xor = xor1 ^ xor2
        xor_hexchar = hex(xor)[2:-1].zfill(32)
        plaintext_hexchar += xor_hexchar
        prev_hexchar = cblock_hexchar
        block_index += 1
    
    return unpad(binascii.unhexlify(plaintext_hexchar))

if __name__ == '__main__':
    print verify(sys.argv[1])
