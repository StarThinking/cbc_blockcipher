from Crypto.Cipher import AES

import binascii

import sys

BLOCK_SIZE = 16

key = binascii.unhexlify('00112233445566778899aabbccddeeff')
iv = '00000000000000000000000000000000'

def pad(s):
    pad_len = BLOCK_SIZE - len(s) % BLOCK_SIZE
    if (pad_len == 0):
        pad_len = BLOCK_SIZE
    print('pad_len (bytes) = ' + str(pad_len))
#    print('s = ' + binascii.hexlify(s))
    return (s + pad_len * chr(pad_len).encode('ascii'))

def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

def encrypt(key, raw):
    cipher = AES.new(key, AES.MODE_ECB)
    raw = pad(raw)
    plaintext_hexchar = binascii.hexlify(raw)
    print 'plaintext_hexchar'
    print plaintext_hexchar
    hexchar_in_block = 32
    block_num = len(binascii.hexlify(raw)) / hexchar_in_block
    block_index = 0
    ciphertext_hexchar = ""
    prev_hexchar = ""

    while block_index < block_num:
        pblock_hexchar = plaintext_hexchar[0:hexchar_in_block]
        print 'pblock_hexchar ' + str(block_index) + ' = ' +  pblock_hexchar
        pblock_int = int(pblock_hexchar, base=16)
        print 'pblock_int'
        print hex(pblock_int)
      
        print 'c = ' + prev_hexchar

        if (block_index == 0):
            iv_int = int(iv, base=16)
            xor_int = pblock_int ^ iv_int
        else:
            prev_int = int(prev_hexchar, base=16)
            print 'prec_int'
            print hex(prev_int)
            xor_int = pblock_int ^ prev_int
        
        print 'xor_int = ' 
        print hex(xor_int)
        print hex(xor_int)[2:-1]
        xor_hexchar = hex(xor_int)[2:-1].zfill(32)
        print 'encrypt xor_hexchar = ' + xor_hexchar
        prev_hexchar = binascii.hexlify(cipher.encrypt(binascii.unhexlify(xor_hexchar)))
        block_index += 1
        plaintext_hexchar = plaintext_hexchar[hexchar_in_block:]
        ciphertext_hexchar += prev_hexchar

    return binascii.unhexlify(ciphertext_hexchar)
    
def decrypt(key, enc):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext_hexchar = ""
    ciphertext_hexchar = binascii.hexlify(enc)
    print 'ciphertext_hexchar'
    print ciphertext_hexchar
    
    cblock_hexchar0 = ciphertext_hexchar[0:32]
    print 'cblock_hexchar0'
    print cblock_hexchar0
    plaintext_hexchar += binascii.hexlify(cipher.decrypt(binascii.unhexlify(cblock_hexchar0)))
    
    cblock_hexchar1 = ciphertext_hexchar[32:64]
    print 'cblock_hexchar1'
    print cblock_hexchar1
    a = binascii.hexlify(cipher.decrypt(binascii.unhexlify(cblock_hexchar1)))
    print 'xor a = ' + a
    b = cblock_hexchar0
    print 'xor b = ' + b
    a_int = int(a, base=16)
    b_int = int(b, base=16)
    xor_int = a_int ^ b_int
    xor_hexchar = hex(xor_int)[2:32].zfill(32)
    print 'xor_hexchar'
    print xor_hexchar

    plaintext_hexchar += xor_hexchar
    #plaintext_hexchar += xor_hexchar
    print 'plaintext_hexchar'
    print plaintext_hexchar
    #dec = cipher.decrypt(binascii.unhexlify(plaintext_hexchar)) 
    return unpad(binascii.unhexlify(plaintext_hexchar))
    
    #cblock_hexchar1 = ciphertext_hexchar[32:64]
    #a = binascii.hexlify(cipher.decrypt(binascii.unhexlify(cblock_hexchar1)))
    #a_int = int(a, base=16)
    #b_int = int(cblock_hexchar0, base=16)
    #xor_int = a_int ^ b_int
    #xor_hexchar = hex(xor_int)[2:32].zfill(32)
    #plaintext_hexchar += xor_hexchar


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
