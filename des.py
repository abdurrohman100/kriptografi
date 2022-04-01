# 3DES not used
# import required module
from Crypto.Cipher import DES3
from hashlib import md5
# using the key
# fernet = Fernet(key)

# def pad(text):
#     n = len(text) % 8
#     return text + (b' ' * n)

key = 'apakabarnya'
keyhash = md5(key.encode('ascii')).digest()
deskey = DES3.adjust_key_parity(keyhash)
enc = DES3.new(deskey, DES3.MODE_EAX,nonce=b'0')
dec = DES3.new(deskey, DES3.MODE_EAX,nonce=b'0')
text1 = b'Python is the Best Language!'

with open('before.txt', 'rb') as enc_file:
	file_bytes = enc_file.read()
	new_file_bytes = enc.encrypt(file_bytes)

# padded_text_enc = pad(encrypted)
print(new_file_bytes)


# opening the encrypted file

# padded_text_enc = pad(text1)
# encrypted_text = des.encrypt(encrypted, des.block_size)
# print(encrypted_text)

# decrypting the file
decrypted = dec.decrypt(new_file_bytes)

print(decrypted)

# opening the file in write mode and
# writing the decrypted data
with open('after.txt', 'wb') as dec_file:
	dec_file.write(new_file_bytes)
	dec_file.write(decrypted)
