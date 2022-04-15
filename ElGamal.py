import random
import math
import sys

class PrivateKey(object):
	def __init__(self, p=0, g=0, x=0, iNumBits=0):
		self.p = int(p)
		self.g = int(g)
		self.x = int(x)
		self.iNumBits = iNumBits
class PublicKey(object):
	def __init__(self, p=None, g=None, h=None, iNumBits=0):
		self.p = p
		self.g = g
		self.h = h
		self.iNumBits = iNumBits
def gcd( a, b ):
		while b != 0:
			c = a % b
			a = b
			b = c
		return a

# hitung base^exp mod modulus
def modexp( base, exp, modulus ):
		return pow(base, exp, modulus)

def SolovayStrassenPrimeTest( num, iConfidence ):
		for i in range(iConfidence):
				#choose random a between 1 and n-2
				a = random.randint( 1, num-1 )
				#if a is not relatively prime to n, n is composite
				if gcd( a, num ) > 1:
						return False
				#declares n prime if jacobi(a, n) is congruent to a^((n-1)/2) mod n
				if not jacobi( a, num ) % num == modexp ( a, (num-1)//2, num ):
						return False
		#if there have been t iterations without failure, num is believed to be prime
		return True

#computes the jacobi symbol of a, n
def jacobi( a, n ):
		if a == 0:
				if n == 1:
						return 1
				else:
						return 0
		#property 1 of the jacobi symbol
		elif a == -1:
				if n % 2 == 0:
						return 1
				else:
						return -1
		#if a == 1, jacobi symbol is equal to 1
		elif a == 1:
				return 1
		#property 4 of the jacobi symbol
		elif a == 2:
				if n % 8 == 1 or n % 8 == 7:
						return 1
				elif n % 8 == 3 or n % 8 == 5:
						return -1
		#property of the jacobi symbol:
		#if a = b mod n, jacobi(a, n) = jacobi( b, n )
		elif a >= n:
				return jacobi( a%n, n)
		elif a%2 == 0:
				return jacobi(2, n)*jacobi(a//2, n)
		#law of quadratic reciprocity
		#if a is odd and a is coprime to n
		else:
				if a % 4 == 3 and n%4 == 3:
						return -1 * jacobi( n, a)
				else:
						return jacobi(n, a )


#Primitive root dari p
#http://modular.math.washington.edu/edu/2007/spring/ent/ent-html/node31.html
def find_primitive_root( p ):
		if p == 2:
				return 1
		p1 = 2
		p2 = (p-1) // p1

		while( 1 ):
				g = random.randint( 2, p-1 )
				if not (modexp( g, (p-1)//p1, p ) == 1):
						if not modexp( g, (p-1)//p2, p ) == 1:
								return g

def find_prime(iNumBits, iConfidence):
		#keep testing until one is found
		while(1):
				p = random.randint( 2**(iNumBits-2), 2**(iNumBits-1) )
				#make sure it is odd
				while( p % 2 == 0 ):
						p = random.randint(2**(iNumBits-2),2**(iNumBits-1))

				#keep doing this if the solovay-strassen test fails
				while( not SolovayStrassenPrimeTest(p, iConfidence) ):
						p = random.randint( 2**(iNumBits-2), 2**(iNumBits-1) )
						while( p % 2 == 0 ):
								p = random.randint(2**(iNumBits-2), 2**(iNumBits-1))
				p = p * 2 + 1
				if SolovayStrassenPrimeTest(p, iConfidence):
						return p

#encodes bytes to integers mod p.  reads bytes from file
def encode(sPlaintext, iNumBits):
		byte_array = bytearray(sPlaintext, 'utf-16')

		z = []
		k = iNumBits//8

		j = -1 * k
		num = 0
		#i iterates through byte array
		for i in range( len(byte_array) ):
				#if i is divisible by k, start a new encoded integer
				if i % k == 0:
						j += k
						num = 0
						z.append(0)
				#add the byte multiplied by 2 raised to a multiple of 8
				z[j//k] += byte_array[i]*(2**(8*(i%k)))

	
		return z

#decodes integers to the original message bytes
def decode(aiPlaintext, iNumBits):
		bytes_array = []

		k = iNumBits//8
		for num in aiPlaintext:
				for i in range(k):
						temp = num
						for j in range(i+1, k):
								temp = temp % (2**(8*j))
						letter = temp // (2**(8*i))
						bytes_array.append(letter)
						num = num - (letter*(2**(8*i)))
		decodedText = bytearray(b for b in bytes_array).decode('utf-16')

		return decodedText

def generate_keys(iNumBits=256, iConfidence=32):
		#p is the prime
		#g is the primitve root
		#x is random in (0, p-1) inclusive
		#h = g ^ x mod p
		p = find_prime(iNumBits, iConfidence)
		g = find_primitive_root(p)
		g = modexp( g, 2, p )
		x = random.randint( 1, (p - 1) // 2 )
		h = modexp( g, x, p )

		publicKey = PublicKey(p, g, h, iNumBits)
		privateKey = PrivateKey(p, g, x, iNumBits)

		return {'privateKey': privateKey, 'publicKey': publicKey}


def encrypt(key, sPlaintext):
		z = encode(sPlaintext, key.iNumBits)

	#cipher_pairs (c, d
		cipher_pairs = []
		for i in z:
				#y ->> (0, p-1)
				y = random.randint( 0, int(key.p) )
				#c = g^y mod p
				c = modexp( key.g, y, key.p )
				#d = ih^y mod p
				d = (i*modexp( key.h, y, key.p)) % key.p
				#add the pair to the cipher pairs list
				cipher_pairs.append( [c, d] )

		encryptedStr = ""
		for pair in cipher_pairs:
				encryptedStr += str(pair[0]) + ' ' + str(pair[1]) + ' '
	
		return encryptedStr

#performs decryption on the cipher pairs found in Cipher using
#prive key K2 and writes the decrypted values to file Plaintext
def decrypt(key, cipher):
		#decrpyts each pair and adds the decrypted integer to list of plaintext integers
		plaintext = []

		cipherArray = cipher.split()
		if (not len(cipherArray) % 2 == 0):
				return "Malformed Cipher Text"
		for i in range(0, len(cipherArray), 2):
				#c = first number in pair
				c = int(cipherArray[i])
				#d = second number in pair
				d = int(cipherArray[i+1])

				#s = c^x mod p
				s = modexp( c, key.x, key.p )
				#plaintext integer = ds^-1 mod p
				plain = (d*modexp( s, key.p-2, key.p)) % key.p
				#add plain to list of plaintext integers
				plaintext.append( plain )

		decryptedText = decode(plaintext, key.iNumBits)

	#remove trailing null bytes
		decryptedText = "".join([ch for ch in decryptedText if ch != '\x00'])

		return decryptedText

def test():
		assert (sys.version_info >= (3,4))
		keys = generate_keys()
		priv = keys['privateKey']
		pub = keys['publicKey']
		print(type(pub))
		message = "My name is Ryan.  Here is some french text:  Maître Corbeau, sur un arbre perché.  Now some Chinese: 鋈 晛桼桾 枲柊氠 藶藽 歾炂盵 犈犆犅 壾, 軹軦軵 寁崏庲 摮 蟼襛 蝩覤 蜭蜸覟 駽髾髽 忷扴汥 "
		cipher = encrypt(pub, message)
		plain = decrypt(priv, cipher)
		print(priv)


		# return message == plain

if __name__=="__main__":
	test();
