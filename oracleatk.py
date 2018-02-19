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
IV = binascii.unhexlify('ffeeddccbbaa99887766554433221100')

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
    # parse command-line arguments
    myargs = getopts(sys.argv)
    # print(myargs)
    if '-d' in myargs: #decryption with hexadecimal string as ciphertext
        hexct = myargs['-d']
        ciphertext = binascii.unhexlify(hexct)
        # The second to last block is C(n-1)
        cnminus1 = hexct[len(hexct)-2*BLOCK_SIZE:len(hexct)-BLOCK_SIZE-1]
        # Modify C(n-1) and send to the padding oracle
        
        # Call the oracle to verify the padding
        output = subprocess.check_output(
            "python oracle.py -d d25a16fe349cded7f6a2f2446f6da1c2", shell=True).rstrip()
        if output[len(output)-1] == 's':
            # WE KNOW PADDING IS CORRECT
        elif:
            # WE KNOW PADDING IS NOT CORRECT
    else:
        # This hex string is the encrypted message (Congratulations! ...)
        print("python cbc.py -d e3ac392ae1d7e9341e1b244791176f6ee19f5a1c9a5c4c6a9e31bd4aa81f75dbf95f427a4757f0ed56ff68567a3b5e78f4cb080de6b18341ee0ac91b18bb2b55")
