import binascii

import sys
import oracle

BLOCK_SIZE = 16

dkcn_dic = {}

def attack_last_byte(Cn_1, Cn):
    #print 'attack_last_byte'
    byte_index = 15
    try_index = 0
    while try_index < 256:
        try_index_hex = hex(try_index)[2:].zfill(2)
        _Cn_1_prime = Cn_1[:30] + try_index_hex
        if (oracle.verify(_Cn_1_prime + Cn) == 'yes'):
            candidate = try_index_hex
            #print 'correct with ' + candidate

            i = 0
            while i < 256: 
                i_hex = hex(i)[2:].zfill(2)
                _Cn_1_prime = Cn_1[:28] + i_hex + candidate
                if (oracle.verify(_Cn_1_prime + Cn) == 'no'):
                    #print 'sorry, candidate ' + candidate + ' is not right'
                    break
                i += 1
            
            if (i == 256):
                #print 'candidate ' + candidate + ' is right!'
                dkcn = int(candidate, base=16) ^ int('01', base=16)
                dkcn_dic[byte_index] = hex(dkcn)[2:].zfill(2)

        try_index += 1
        
def attack_other_byte(Cn_1, Cn, _byte_index):
    #print 'attack_other_byte ' + str(_byte_index)
    byte_index = _byte_index
    assumed_pad = BLOCK_SIZE - byte_index
    pad_hex = hex(assumed_pad)[2:].zfill(2)

    try_index = 0
    while try_index < 256:
        try_index_hex = hex(try_index)[2:].zfill(2)

        rear_bytes_hex = ''
        i = 1
        while (i + byte_index) < BLOCK_SIZE:
            dk_hex = dkcn_dic[byte_index + i]
            rear_byte = int(dk_hex, base=16) ^ int(pad_hex, base=16)
            rear_byte_hex = hex(rear_byte)[2:].zfill(2)
            rear_bytes_hex += rear_byte_hex
            i += 1

        #print 'rear_bytes_hex = ' + rear_bytes_hex
        _Cn_1_prime = Cn_1[:byte_index*2] + try_index_hex + rear_bytes_hex
        #print '_Cn_1_prime = ' + _Cn_1_prime

        if (oracle.verify(_Cn_1_prime + Cn) == 'yes'):
            candidate = try_index_hex
            #print 'correct with ' + candidate
            dkcn = int(candidate, base=16) ^ int(pad_hex, base=16)
            dkcn_dic[byte_index] = hex(dkcn)[2:].zfill(2)

        try_index += 1

def unpad(s):
     #print('unpad s = ' + binascii.hexlify(s))
    return s[:-ord(s[len(s) - 1:])]

def attack(Cn_1, Cn, last_block):
    attack_last_byte(Cn_1, Cn)
   
    byte_index = 14
    while byte_index >= 0:
        attack_other_byte(Cn_1, Cn, byte_index)
        #print dkcn_dic[byte_index]
        byte_index -= 1

    final_dkcn_hex = ''
    i = 0
    while i < BLOCK_SIZE:
        final_dkcn_hex += dkcn_dic[i]
        i += 1
    #print 'final_dkcn_hex = ' + final_dkcn_hex

    Pn = int(Cn_1, base=16) ^ int(final_dkcn_hex, base=16)
    Pn_hex = hex(Pn)[2:-1].zfill(BLOCK_SIZE*2)
    print 'Pn_hex = ' + Pn_hex

    if (last_block == 'no'):
        print binascii.b2a_qp(binascii.unhexlify(Pn_hex))
    else:
        print binascii.b2a_qp(unpad(binascii.unhexlify(Pn_hex)))
    
if __name__ == '__main__':
    Cn_1 = sys.argv[1]
    Cn = sys.argv[2]
    last_block = sys.argv[3]
    attack(Cn_1, Cn, last_block)
