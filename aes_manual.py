import hashlib

debug = 0

s_box = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

inverse_s_box = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
                0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
                0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
                0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
                0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
                0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
                0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
                0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
                0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
                0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
                0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
                0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
                0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
                0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
                0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
                0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]

rj = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# 0  4  8  12     0  4  8  12
# 1  5  9  13     5  9  13 1
# 2  6  10 14     10 14 2  6 
# 3  7  11 15     15 3  7  11
shift_row_indiced = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
# 0  4  8  12     0  4  8  12
# 1  5  9  13     13 1  5  9
# 2  6  10 14     10 14 2  6 
# 3  7  11 15     7  11 15 3
inverse_shift_row_indiced = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]

column_switcher = [[2, 3, 1, 1], 
                   [1, 2, 3, 1], 
                   [1, 1, 2, 3], 
                   [3, 1, 1, 2]]

inverse_column_switcher = [[0x0e, 0x0b, 0x0d, 0x09], 
                           [0x09, 0x0e, 0x0b, 0x0d], 
                           [0x0d, 0x09, 0x0e, 0x0b], 
                           [0x0b, 0x0d, 0x09, 0x0e]]       
class AESBlock(object):
    def __init__(self, key : bytes, block : bytes):
        self.block_size = 16
        self.immutable_block = block
        self.block = bytearray(self.immutable_block)
        self.key = key
        self.__keyExpansion()
    def __keyExpansion(self):
        self.words = [None] * 44
        if debug:
            print("ROUND KEY")
        for i in range(4):
            self.words[i] = bytearray(4)
            self.words[i][0] = self.key[4*i]
            self.words[i][1] = self.key[4*i + 1]
            self.words[i][2] = self.key[4*i + 2]
            self.words[i][3] = self.key[4*i + 3]
            if debug:
                printArray(self.words[i])
        for i in range(4, 44, 1):
            self.words[i] = bytearray(4)
            temp = self.words[i-1]
            if i % 4 == 0 :
                temp = self.__subWord(self.__rotWord(temp))
                temp[0] ^= rj[int(i/4)-1]
            for j in range(4):
                self.words[i][j] = self.words[i-4][j] ^ temp[j]
            if debug:
                printArray(self.words[i])
                print()
    def __rotWord(self, word):
        output = bytearray(4)
        output[0] = word[1]
        output[1] = word[2]
        output[2] = word[3]
        output[3] = word[0]
        return output
    def __subWord(self, word):
        output = bytearray(4)
        for i in range(4):
            output[i] = s_box[word[i]]
        return output
    def encrypt(self):
        self.block = bytearray(self.immutable_block)
        self.__addKey(0)
        for i in range(9):
            self.__subtituteBytes()
            self.__shiftRows()
            self.__mixColumns()
            self.__addKey((i+1)*4)
        self.__subtituteBytes()
        self.__shiftRows()
        self.__addKey(40)
        return self.block
    def __subtituteBytes(self):
        for i in range(self.block_size):
            self.block[i] = s_box[self.block[i]]
        if debug:
            print("SUBTITUTING BYTES")
            printBlock(self.block)
            print()
    def __shiftRows(self):
        output = bytearray(16)
        for i in range(self.block_size):
            output[i] = self.block[shift_row_indiced[i]]
        self.block = output
        if debug:
            print("SHIFTING ROWS")
            printBlock(self.block)
            print()
    def __mixColumns(self):
        outputByte = bytearray(16)
        for start in range(0, 16, 4):
            for i in range(4) :
                output = 0
                for j in range(4) :
                    multiplier = column_switcher[i][j]
                    result = 0
                    if(multiplier == 1):
                        result = self.block[start+j]
                    elif multiplier == 2 :
                        result = multiplyBy2(self.block[start+j])
                    elif multiplier == 3 :
                        result = multiplyBy3(self.block[start+j])
                    output ^= result
                outputByte[start+i] = output
        self.block = outputByte
        if debug:
            print("MIXING COLUMNS")
            printBlock(self.block)
            print()
    def decrypt(self):
        self.block = bytearray(self.immutable_block)
        self.__addKey(40)
        self.__inverseShiftRows()
        self.__inverseSubtituteBytes()
        for i in range(8, -1, -1):
            self.__addKey((i+1)*4)
            self.__inverseMixColumns()
            self.__inverseShiftRows()
            self.__inverseSubtituteBytes()
        self.__addKey(0)
        return self.block
    def __inverseSubtituteBytes(self):
        for i in range(self.block_size):
            self.block[i] = inverse_s_box[self.block[i]]
        if debug:
            print("INVERSE SUBTITUTING BYTES")
            printBlock(self.block)
            print()
    def __inverseShiftRows(self):
        output = bytearray(16)
        for i in range(self.block_size):
            output[i] = self.block[inverse_shift_row_indiced[i]]
        self.block = output
        if debug:
            print("INVERSE SHIFTING ROWS")
            printBlock(self.block)
            print()
    def __inverseMixColumns(self):
        outputByte = bytearray(16)
        for start in range(0, 16, 4):
            for i in range(4) :
                output = 0
                for j in range(4) :
                    multiplier = inverse_column_switcher[i][j]
                    result = 0
                    if multiplier == 9:
                        result = multiplyBy9(self.block[start+j])
                    elif multiplier == 11:
                        result = multiplyBy11(self.block[start+j])
                    elif multiplier == 13:
                        result = multiplyBy13(self.block[start+j])
                    elif multiplier == 14:
                        result = multiplyBy14(self.block[start+j])
                    output ^= result
                outputByte[start+i] = output
        self.block = outputByte
        if debug:
            print("INVERSE MIXING COLUMNS")
            printBlock(self.block)
            print()
    def __addKey(self, offset):
        for i in range(4):
            for j in range(4):
                self.block[i*4+j] = self.block[i*4+j] ^ self.words[offset+i][j]
        if debug:
            print(f"ADDING KEYS {offset}-{offset+3}")
            printBlock(self.block)
            print()

def multiplyBy2(byte):
    output = byte << 1
    if byte & 128:
        output ^= 0x1b
    output %= 256
    return output

def multiplyBy3(byte):
    return byte ^ multiplyBy2(byte)

def printBlock(byte):
    for i in range(4):
        for j in range(4):
            print(hex(byte[i+j*4]), end='\t')
        print()

def printArray(byte, offset=0):
    for i in range(offset, offset+4, 1):
        print(hex(byte[i]), end='\t')
    print()

def multiplyBy2(byte):
    output = byte << 1
    if byte & 128:
        output ^= 0x1b
    # print(f"{byte} * 2 = {output}")
    output &= 0xff
    # print(f"{byte} * 2 = {output}")
    return output

def multiplyBy3(byte):
    return byte ^ multiplyBy2(byte)

def multiplyBy9(byte):
    return multiplyBy2(multiplyBy2(multiplyBy2(byte))) ^ byte

def multiplyBy11(byte):
    return multiplyBy2(multiplyBy2(multiplyBy2(byte)) ^ byte) ^ byte

def multiplyBy13(byte):
    return multiplyBy2(multiplyBy2(multiplyBy2(byte) ^ byte)) ^ byte

def multiplyBy14(byte):
    return multiplyBy2(multiplyBy2(multiplyBy2(byte) ^ byte) ^ byte)

def byte_xor(ba1, ba2):
        return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

class CBC(object):

    def __init__(self, key : bytes, message : bytes, iv : bytes):
        self.block_size = 16
        self.immutable_message = message
        self.message = bytearray(self.immutable_message)
        self.key = key
        self.iv = iv
        self.ciphered = []
        self.deciphered = []
        self.__seperateChunks()

    def __seperateChunks(self):
        self.chunks = [self.message[i:i+self.block_size] for i in range(0, len(self.message), self.block_size)]
        self.chunksCount = len(self.chunks)

    def encrypt(self):
        # 1st chunk with iv
        aes = AESBlock(self.key, byte_xor(self.chunks[0], self.iv))
        self.ciphered.append(aes.encrypt())
    
        if (self.chunksCount < 2):
            return self.ciphered[0]
        
        # rest of the chunks
        for i in range(1, self.chunksCount):
            aes = AESBlock(self.key, byte_xor(self.chunks[i], self.ciphered[i-1]))
            self.ciphered.append(aes.encrypt())
        
        # return self.ciphered                              # return list
        return self.__concatByteArray(self.ciphered)      # return concat list

    def decrypt(self):
        # 1st chunk with iv
        aes = AESBlock(self.key, self.chunks[0])
        self.deciphered.append(byte_xor(aes.decrypt(), self.iv))

        if (self.chunksCount < 2):
            return self.deciphered[0]

        # rest of chunks
        for i in range(1, self.chunksCount):
            aes = AESBlock(self.key, self.chunks[i])
            self.deciphered.append(byte_xor(aes.decrypt(), self.chunks[i-1]))

        # return self.deciphered                            # return list
        return self.__concatByteArray(self.deciphered)      # return concat list

    def __concatByteArray(self, bArray):
        res = b''
        for i in range(0, self.chunksCount):
            res+=bArray[i]
        return res


from time import time
if __name__=="__main__":
    # hash = hashlib.md5("acsjaldfdbsriddd".encode())
    # key = "Thats my Kung Fu".encode()
    # bytes_a = "Two One Nine Two".encode()

    # print("KEY")
    # printBlock(key)
    # print()

    # print("TEXT")
    # printBlock(bytes_a)
    # print()

    # aes = AESBlock(key, bytes_a)
    # encrypted = aes.encrypt()
    # print("ENCRYPTED")
    # printBlock(encrypted)
    # print()

    # aesEnc = AESBlock(key, encrypted)
    # print("DECRYPTED")
    # decrypted = aesEnc.decrypt()
    # printBlock(decrypted)
    # print()


    
    # ! cbc encrypt
    iv = "zxcvasdfqwerpoiu".encode()
    key = "abcdjklauiofjdjd".encode()
    message = "aaaaaaaaaaaaaaaxybbbbbbbbbbbbbbb".encode()
    chunks = [message[i:i+16] for i in range(0, len(message), 16)]

    t0 = time()
    # ! testing cbc encrypt
    cbc = CBC(key, message, iv)
    cbc_enc = cbc.encrypt()
    t1 = time()
    # cbc_enc_concat = b''
    # for i in range(0, len(cbc_enc)):  # kalau hasil nya list, di concat dulu sebelum di decr
    #     cbc_enc_concat+=cbc_enc[i]

    print('encryption took ' + str(t1-t0)+ ' seconds')

    # ! testing cbc decrypt
    cbc = CBC(key, cbc_enc, iv)
    cbc_dec = cbc.decrypt()
    t2 = time()

    print('message')
    printBlock(chunks[0])
    printBlock(chunks[1])
    print('decrypted')
    printBlock(cbc_dec)
    # printBlock(cbc_dec[0])
    # printBlock(cbc_dec[1])
    print()

    print('decryption took ' + str(t2-t1) + ' seconds')
