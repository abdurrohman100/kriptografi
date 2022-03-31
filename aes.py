import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from aes_manual import CBC
from base64 import b64encode, b64decode

class AESCipher(object):
    def __init__(self, key, scratch = False):
        self.block_size = AES.block_size
        self.scratch = scratch
        if(scratch):
            self.key = hashlib.md5(key.encode()).digest()
        else :
            self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        if self.scratch :
            cipher = CBC(self.key, plain_text.encode(), iv)
            encrypted_text = cipher.encrypt()
        else :
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def encrypt_byte(self, byte):
        byte = self.__pad_byte(byte)
        iv = Random.new().read(self.block_size)
        # print(iv)
        if self.scratch :
            cipher = CBC(self.key, byte, iv)
            encrypted_byte = cipher.encrypt()
            # return iv + encrypted_byte
        else :
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            # print
            # cipher = AES.new(self.key, AES.MODE_CBC)
            encrypted_byte = cipher.encrypt(byte)
            # return encrypted_byte
        return iv + encrypted_byte

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        
        if self.scratch :
            cipher = CBC(self.key, encrypted_text[self.block_size:], iv)
            try:
                plain_text = cipher.decrypt().decode("utf-8")
                return self.__unpad(plain_text)
            except:
                plain_text = " Cannot decrypt"
        else :
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            try:
                plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
                return self.__unpad(plain_text)
            except:
                plain_text = " Cannot decrypt"
        return plain_text

    def decrypt_byte(self, encrypted_byte):
        iv = encrypted_byte[:self.block_size]
        print(self.block_size)
        print(iv)
        if self.scratch :
            cipher = CBC(self.key, encrypted_byte[self.block_size:], iv)
            byte = cipher.decrypt()
        else :
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            byte = cipher.decrypt(encrypted_byte[self.block_size:])
        return self.__unpad(byte)

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    def __pad_byte(self, byte):
        byte_array = bytearray(byte)
        number_of_bytes_to_pad = self.block_size - len(byte_array) % self.block_size
        for i in range(0, number_of_bytes_to_pad) :
            byte_array.append(number_of_bytes_to_pad)
        return bytes(byte_array)

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        return plain_text[:-ord(last_character)]

    @staticmethod
    def __unpad_byte(byte):
        last_byte = byte[len(byte) - 1:]
        return byte[:-ord(last_byte)]

from time import time
if __name__=="__main__":
    aes = AESCipher("abcdjklauiofjdjd", True)
    t0 = time()
    enc = aes.encrypt_byte("aaaaaaasassssssssssaaaaaaaaaxybbbbbbbbbbbbbbb".encode())
    t1 = time()
    # print(b64encode(enc).decode())
    dec = aes.decrypt_byte(enc)
    t2 = time()