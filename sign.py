from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import ED_byteSeq

# encryption
plaintext = b'secret data'
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_EAX)
ciphertext, digest = cipher.encrypt_and_digest(plaintext)
nonce = cipher.nonce

# decryption
cipher = AES.new(key, AES.MODE_EAX,nonce)
decrypted = cipher.decrypt_and_verify(ciphertext,digest)
print(decrypted)



# sign and verify the signature

PR = (13,77) # PR of the sender
signature = ED_byteSeq.rsaEncryptBytes2Bytes(PR,digest)

PU = (37,77) # PU of the sender
decryptedDigest = ED_byteSeq.rsaDecryptBytes2Bytes(PU,signature)

if digest == decryptedDigest:
    print('the signature:', signature, 'belongs to the user with PU = ', PU)
else:
    print('the signature:', signature, 'does not belong to the user with PU = ', PU)





