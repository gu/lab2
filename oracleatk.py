# Import AES symmetric encryption cipher
from Crypto.Cipher import AES

# Import class for hexadecimal string processing
import binascii

# support command-line arguments
import sys

# define block size of AES encryption
BLOCK_SIZE = 16

# the 128-bit AES key
key = binascii.unhexlify('00112233445566778899aabbccddeeff')

# the 128-bit Initial value 
IV = binascii.unhexlify('ec96611de5aece583b8e07a3013d4ede')

# The function to apply PKCS #5 padding to a block
def pad(s):
    pad_len = BLOCK_SIZE - len(s) % BLOCK_SIZE
    if (pad_len == 0):
        pad_len = BLOCK_SIZE
    return (s + pad_len * chr(pad_len).encode('ascii'))

# The function to remove padding
def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def xor(a, b):
    ret = ''
    for i in range(0, len(a)):
        ret = ret + chr((ord(a[i:i+1]) ^ ord(b[i:i+1])))
    return ret


def ecb_encrypt(key, raw):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(raw)

def encrypt(key, raw):
    raw = pad(raw)
    enc = ''
    enc_sub = ''

    for x in range(0, len(raw) / BLOCK_SIZE):
        raw_sub = raw[x*BLOCK_SIZE:(x+1)*BLOCK_SIZE]
        raw_sub = xor(raw_sub, IV if x == 0 else enc_sub)
        enc_sub = ecb_encrypt(key, raw_sub)
        enc = enc + enc_sub

    return enc

def ecb_decrypt(key, enc):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(enc)

def oracle(key, enc):
    dec = ''
    enc_sub = ''
    enc_pre = ''

    for x in range(0, len(enc) / BLOCK_SIZE):
        enc_sub = enc[x*BLOCK_SIZE:(x+1)*BLOCK_SIZE]
        dec_sub = ecb_decrypt(key, enc_sub)
        dec_sub = xor(dec_sub, IV if x == 0 else enc_pre)
        dec = dec + dec_sub
        enc_pre = enc_sub
        
    # We now have the original, padded plaintext.
    # We must check the correctness.

    padbit = dec[-1:]
    padnum = ord(padbit)
    for b in range(0, padnum):
        if (dec[len(dec) - 1 - b] != padbit):
            return 0
    if padnum == 0:
        for i in range(1, 17):
            if (dec[len(dec) - i] != padbit):
                return 0
    return 1

def getopts(argv):
    opts = {}
    while argv:
        if argv[0][0] == '-':
            opts[argv[0]] = argv[1]
        argv = argv[1:]
    return opts

if __name__ == '__main__':
    # parse command-line arguments
    myargs = getopts(sys.argv)
    # print(myargs)
    if '-d' in myargs: #decryption with hexadecimal string as ciphertext
        hexct = myargs['-d']
        ciphertext = binascii.unhexlify(hexct)
        # The second to last block is C(n-1)
        czero = hexct[:-2*(BLOCK_SIZE*2)]
        cnminus1 = hexct[-2*(BLOCK_SIZE*2):-1*(BLOCK_SIZE*2)]
        if (len(hexct) == 2*BLOCK_SIZE):
            cnminus1 = binascii.hexlify(IV)
        cnminus1prime = cnminus1
        cn = hexct[-1*(BLOCK_SIZE*2):]

        d = ''
        p = ''
        
        potential_values = [None] * 2
        for d_ctr in range(1, 17):
            saved_byte = cnminus1[len(cnminus1)-(2*d_ctr):len(cnminus1)-(2*(d_ctr-1))]
            output_count = 0
            for i in range(0, 256):
                new_byte = hex(i)[ -1 if i < 16 else -2 :]
                if i < 16:
                    new_byte = '0' + new_byte

                cnminus1primelist = list(cnminus1prime)
                cnminus1primelist[len(cnminus1)-(2*d_ctr):len(cnminus1)-(2*(d_ctr-1))] = new_byte
                cnminus1prime = "".join(cnminus1primelist)
            
                cprime = czero + cnminus1prime + cn
                if oracle(key, binascii.unhexlify(cprime)):
                    potential_values[output_count] = cnminus1prime
                    output_count = output_count + 1
            if d_ctr == 1 and output_count == 2:

                cnminus1primelist = list(potential_values[0])
                cnminus1primelist[-4:-2] = binascii.hexlify(xor(binascii.unhexlify(potential_values[0][-4:-2]), binascii.unhexlify('01')))
                output = oracle(key, binascii.unhexlify(czero + "".join(cnminus1primelist) + cn))
                if output == 0:
                    cnminus1prime = potential_values[1]
                cnminus1prime = potential_values[0]
            else:
                cnminus1prime = potential_values[0]

            pnprime_byte = '0' + hex(d_ctr)[-1:] # assumption byte
            d_byte = binascii.hexlify(xor(binascii.unhexlify(cnminus1prime[len(cnminus1prime)-2*d_ctr:len(cnminus1prime)-2*(d_ctr-1)]), binascii.unhexlify(pnprime_byte)))
            d = d_byte + d

            p_byte = binascii.hexlify(xor(binascii.unhexlify(cnminus1[len(cnminus1)-2*d_ctr:len(cnminus1)-2*(d_ctr-1)]), binascii.unhexlify(d_byte)))
            p = p_byte + p

            cnminus1primelist = list(cnminus1prime)

            for x in range(1,d_ctr+1):
                cnminus1primelist[len(cnminus1primelist) - 2*x:len(cnminus1primelist) - 2*(x-1)] = binascii.hexlify(xor(binascii.unhexlify(d[len(d) - 2*x:len(d) - 2*(x-1)]), binascii.unhexlify('0' + hex(d_ctr+1)[-1:])))
            cnminus1prime = "".join(cnminus1primelist)
            potential_values = [None] * 2

        p = unpad(binascii.unhexlify(p))
        print('Plaintext: ' + p)

    else:
        # This hex string is the encrypted message (Congratulations! ...)
        print("python oracleatk.py -d 5a121b376144ed5be657869d1246ca68")
        print("python oracleatk.py -d dfa314c8787fba9532394379075e715b9a4922d00889698ad59c8108eeb02ef694103121f818153a2036016ec182287c3de6fafa93f62d57f3061963654865b0")