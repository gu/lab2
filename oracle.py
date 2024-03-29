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

# The function to remove padding
def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def xor(a, b):
    ret = ''
    for i in range(0, BLOCK_SIZE):
        ret = ret + chr((ord(a[i:i+1]) ^ ord(b[i:i+1])))
    return ret

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
            print('Padding correct? ---> No')
            return 0
    if padnum == 0:
        for i in range(1, 17):
            if (dec[len(dec) - i] != padbit):
                print('Padding correct? ---> No')
                return 0
    print('Padding correct? ---> Yes')
    return 1

def getopts(argv):
    opts = {}
    while argv:
        if argv[0][0] == '-':
            opts[argv[0]] = argv[1]
        argv = argv[1:]
    return opts

if __name__ == '__main__':
    myargs = getopts(sys.argv)
    if '-d' in myargs:
        ciphertext = binascii.unhexlify(myargs['-d'])
        oracle(key, ciphertext)
    else:
        print('python oracle.py -d 4113e9e37d7284edcedc56deb0171d2e')
