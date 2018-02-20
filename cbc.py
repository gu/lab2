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
    for i in range(0, BLOCK_SIZE):
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

def decrypt(key, enc):
    dec = ''
    enc_sub = ''
    enc_pre = ''

    for x in range(0, len(enc) / BLOCK_SIZE):
        enc_sub = enc[x*BLOCK_SIZE:(x+1)*BLOCK_SIZE]
        dec_sub = ecb_decrypt(key, enc_sub)
        dec_sub = xor(dec_sub, IV if x == 0 else enc_pre)
        dec = dec + dec_sub
        enc_pre = enc_sub

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
        print('CipherText: ' + binascii.hexlify(ciphertext))
    elif '-u' in myargs:
        ciphertext = binascii.unhexlify(myargs['-u'])
        plaintext = decrypt(key, ciphertext)
        print('Plaintext: ' + binascii.b2a_qp(plaintext))
    else:
        print('python cbc.py -e 010203040506')
        print("python cbc.py -s 'this is cool'")
        print('python cbc.py -d 21f570f8e55f0f090260bb863b6a5780')
        print('python cbc.py -u 36b6b04d109dce310bf84df6b0f65cc8')
