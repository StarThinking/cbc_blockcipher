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
    print 's = ' + binascii.hexlify(s)
    print 'len(s)'
    print len(s)
    print 's[15:]'
    print binascii.hexlify(s[15:])
    print 'ord'
    print -ord(s[len(s) - 1:])
    return s[:-ord(s[len(s) - 1:])]

def encrypt(key, raw):
    cipher = AES.new(key, AES.MODE_ECB)
    raw = pad(raw)
    plaintext_hexchar = binascii.hexlify(raw)
    block_num = len(plaintext_hexchar) / hexchar_in_block
    block_index = 0
    ciphertext_hexchar = ""
    prev_hexchar = ""

    while block_index < block_num:
        pblock_hexchar = plaintext_hexchar[0:hexchar_in_block]
        pblock_int = int(pblock_hexchar, base=16)
      
        if (block_index == 0):
            iv_int = int(iv, base=16)
            xor_int = pblock_int ^ iv_int
        else:
            prev_int = int(prev_hexchar, base=16)
            xor_int = pblock_int ^ prev_int
       
        # remove '0x and L'
        xor_hexchar = hex(xor_int)[2:-1].zfill(32)
        prev_hexchar = binascii.hexlify(cipher.encrypt(binascii.unhexlify(xor_hexchar)))
        plaintext_hexchar = plaintext_hexchar[hexchar_in_block:]
        ciphertext_hexchar += prev_hexchar
        block_index += 1

    return binascii.unhexlify(ciphertext_hexchar)
    
def decrypt(key, enc):
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
