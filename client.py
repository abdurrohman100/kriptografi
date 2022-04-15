import base64
import logging
import socket
import os
import json
from DiffieHellman import DiffieHellman
from ElGamal import *
from aes import AESCipher
from Crypto.Cipher import DES3
from hashlib import md5

# AESC = AESCipher("kijpakbas", True)

diffieHelman = DiffieHellman()




# AESDict = {}

TARGET_IP = "127.0.0.1"
# TARGET_IP = "167.172.77.139"
TARGET_PORT = 8889

# cipher = AESCipher("ini key", True)

class ChatClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = (TARGET_IP,TARGET_PORT)
        self.sock.connect(self.server_address)
        self.username=""
        self.tokenid=""
        self.elpublic=PublicKey()
        self.elprivate=PrivateKey()
    def proses(self,cmdline):
        j=cmdline.split(" ")
        try:
            command=j[0].strip()
            if (command=='auth'):
                username=j[1].strip()
                password=j[2].strip()
                response = self.login(username,password)
                return response
            elif (command=='generate_elgamalKey'):
                return self.sendkey_elgamal()
            elif (command=='update_elgamalKey'):
                return self.update_elgamal()
            elif (command=='send_aes'):
                usernameto = j[1].strip()
                filename = j[2].strip()
                pkey = j[3].strip()
                return self.sendfile_aes(usernameto,filename,pkey)
            elif (command=='send_3des'):
                usernameto = j[1].strip()
                filename = j[2].strip()
                pkey = j[3].strip()
                return self.sendfile_3des(usernameto,filename,pkey)
            elif (command=='send_elgamal'):
                usernameto = j[1].strip()
                filename = j[2].strip()
                return self.sendfile_elgamal(usernameto,filename)
            elif (command=='my_file'):
                return self.myfile()
            elif (command=='download_aes'):
                username = j[1].strip()
                filename = j[2].strip()
                pkey = j[3].strip()
                return self.downloadfile_aes(username, filename,pkey)
            elif (command=='download_3des'):
                username = j[1].strip()
                filename = j[2].strip()
                pkey = j[3].strip()
                return self.downloadfile_3des(username, filename,pkey)
            elif (command=='download_elgamal'):
                username = j[1].strip()
                filename = j[2].strip()
                return self.downloadfile_elgamal(username, filename)
            elif (command=='sendkey'):
                key = j[1].strip()
                return self.sendkey(key)
            elif (command=='getkey'):
                username = j[1].strip()
                return self.getkey(username)
            else:
                return "*Maaf, command tidak benar"
        except IndexError:
                return "-Maaf, command tidak benar"
    def sendstring(self,string):
        try:
            self.sock.sendall(string.encode())
            receivemsg = ""
            while True:
                data = self.sock.recv(64)
                # print("diterima dari server",data)
                if (data):
                    receivemsg = "{}{}" . format(receivemsg,data.decode())  #data harus didecode agar dapat di operasikan dalam bentuk string
                    if receivemsg[-4:]=='\r\n\r\n':
                        # print("end of string")
                        return json.loads(receivemsg)
        except:
            self.sock.close()
            return { 'status' : 'ERROR', 'message' : 'Gagal'}
    def login(self,username,password):
        string="auth {} {} \r\n" . format(username,password)
        result = self.sendstring(string)
        if result['status']=='OK':
            self.tokenid=result['tokenid']
            self.username = username
            
            self.proses(f"sendkey {diffieHelman.publicKey}")
            return { 'status' : 'OK', 'message' : 'Logged In', 'username':username, 'token':self.tokenid}
        else:
            return { 'status' : 'ERROR', 'message' : 'Wrong Password or Username'}
        
    def sendfile_aes(self, usernameto, filename,key):
        if(self.tokenid==""):
            return "Error, not authorized"
        try :
            file = open(filename, "rb")
        except FileNotFoundError :
            return "Error, {} file not found".format(filename)
        # cipher2 = AESCipher("ini key1", True)
        cipher2 = AESCipher(key, True) 
        buffer = file.read()
        encrypted_buffer = cipher2.encrypt_byte(buffer)
        encrypted_file = open(filename+".enc", "wb")
        encrypted_file.write(encrypted_buffer)
        file.close()
        encrypted_file.close()
        buffer_string = base64.b64encode(encrypted_buffer).decode('utf-8')
        message="send_file_aes {} {} {} {} {} \r\n" .format(self.tokenid, usernameto, filename,key, buffer_string)
        result = self.sendstring(message)
        if result['status']=='OK':
            return {'status' : 'OK', 'message':'file sent to {}' . format(usernameto)}
        else:
            return {'status':'ERROR', 'message':'Error, {}' . format(result['message'])}
    def getElgamalkey(self, username):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="getelgamalkey {} {} \r\n" . format(self.tokenid,username)
        result = self.sendstring(string)
        if result['status']=='OK':
            return PublicKey(int(result['p']),int(result['g']),int(result['h']),256)
            # return {'status':'OK', 'key':result['key']}
        else:
            return {'status':'ERROR', 'message':'Error, {}' . format(result['message'])}
    
    def getMyElgamalkey(self, username):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="getelgamalkey {} {} \r\n" . format(self.tokenid,username)
        result = self.sendstring(string)
        if result['status']=='OK':
            return PublicKey(int(result['p']),int(result['g']),int(result['h']),256)
            # return {'status':'OK', 'key':result['key']}
        else:
            return {'status':'ERROR', 'message':'Error, {}' . format(result['message'])}
    
    def sendfile_elgamal(self, usernameto, filename):
        if(self.tokenid==""):
            return "Error, not authorized"
        try :
            file = open(filename, "r")
        except FileNotFoundError :
            return "Error, {} file not found".format(filename)
        buffer = file.read()
        publicKey= self.getElgamalkey(usernameto)

        encrypted_buffer = encrypt(publicKey, buffer)
        encrypted_file = open(filename+".egml", "w")
        encrypted_file.write(encrypted_buffer)
        file.close()
        encrypted_file.close()
        buffer_string = base64.b64encode(encrypted_buffer.encode('utf-8')).decode('utf-8')
        message="send_file_elgamal {} {} {} {} \r\n" .format(self.tokenid, usernameto, filename, buffer_string)
        result = self.sendstring(message)
        if result['status']=='OK':
            return {'status' : 'OK', 'message':'file sent to {} with P : {}' . format(usernameto,publicKey.p)}
        else:
            return {'status':'ERROR', 'message':'Error, {}' . format(result['message'])}
    
    def sendfile_3des(self, usernameto, filename,key):
        if(self.tokenid==""):
            return "Error, not authorized"
        try :
            file = open(filename, "rb")
        except FileNotFoundError :
            return "Error, {} file not found".format(filename)
        # cipher2 = AESCipher("ini key1", True)
        keyhash = md5(key.encode('ascii')).digest()
        deskey = DES3.adjust_key_parity(keyhash)
        enc = DES3.new(deskey, DES3.MODE_EAX,nonce=b'0')
        buffer = file.read()
        encrypted_buffer = enc.encrypt(buffer)
        encrypted_file = open(filename+".enc", "wb")
        encrypted_file.write(encrypted_buffer)
        file.close()
        encrypted_file.close()
        buffer_string = base64.b64encode(encrypted_buffer).decode('utf-8')
        message="send_file_3des {} {} {} {} {} \r\n" .format(self.tokenid, usernameto, filename,key, buffer_string)
        result = self.sendstring(message)
        if result['status']=='OK':
            return {'status' : 'OK', 'message':'file sent to {}' . format(usernameto)}
        else:
            return {'status':'ERROR', 'message':'Error, {}' . format(result['message'])}
    def myfile(self):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="my_file {} \r\n" . format(self.tokenid)
        result = self.sendstring(string)
        if result['status']=='OK':
            return "{}" . format(json.dumps(result['messages']))
        else:   
            return {'status':'ERROR', 'message':'Error, {}' . format(result['message'])}
    
    def downloadfile_elgamal(self, username, filename):
        if (self.tokenid==""):
            return "Error, not authorized"
        if self.elprivate.x==0:
            return "Missing Key"
        string="download_file_elgamal {} {} {} \r\n" . format(self.tokenid, username, filename)
        result = self.sendstring(string)
        if result['status']=='OK':
            output_file = open(result['filename'], 'w')
            
            decrypted_buffer = decrypt(self.elprivate, base64.b64decode(result['data']))
            output_file.write(decrypted_buffer)
            output_file.close()
            return {'status' : 'OK', 'message':'file {} P: {} downloaded' . format(filename,self.elprivate.p)}
        else:
            return {'status':'ERROR', 'message':'Error, {}' . format(result['message'])}
    def downloadfile_aes(self, username, filename,key):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="download_file_aes {} {} {} \r\n" . format(self.tokenid, username, filename,key)
        result = self.sendstring(string)
        if result['status']=='OK':
            # cipher3 = AESCipher("ini key1", True) 
            cipher3 = AESCipher(key, True) 
            output_file = open(result['filename'], 'wb')
            decrypted_buffer = cipher3.decrypt_byte(base64.b64decode(result['data']))
            output_file.write(decrypted_buffer)
            output_file.close()
            return {'status' : 'OK', 'message':'file {} downloaded' . format(filename)}
        else:
            return {'status':'ERROR', 'message':'Error, {}' . format(result['message'])}
    def downloadfile_3des(self, username, filename,key):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="download_file_3des {} {} {} \r\n" . format(self.tokenid, username, filename,key)
        result = self.sendstring(string)
        if result['status']=='OK':
            # cipher3 = AESCipher("ini key1", True) 
            keyhash = md5(key.encode('ascii')).digest()
            deskey = DES3.adjust_key_parity(keyhash)
            dec = DES3.new(deskey, DES3.MODE_EAX,nonce=b'0')
            output_file = open(result['filename'], 'wb')
            decrypted_buffer = dec.decrypt(base64.b64decode(result['data']))
            output_file.write(decrypted_buffer)
            output_file.close()
            return {'status' : 'OK', 'message':'file {} downloaded' . format(filename)}
        else:
            return {'status':'ERROR', 'message':'Error, {}' . format(result['message'])}

    def sendkey(self, key):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="sendkey {} {} \r\n" . format(self.tokenid,key)
        result = self.sendstring(string)
        if result['status']=='OK':
            return "{}" . format(json.dumps(result['messages']))
        else:
            return {'status':'ERROR', 'message':'Error, {}' . format(result['message'])}
    def update_elgamal(self):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="update_elgamal {}\r\n" . format(self.tokenid)
        result = self.sendstring(string)
        if result['status']=='OK':
            if result['p']!=0:
                elgamalPublicKey=PublicKey(result['p'],result['g'],result['h'],256)
                elgamalPrivateKey=PrivateKey(result['p'],result['g'],result['x'],256)
                return {'status':'OK', 'message':'Key Fetched from Server {} {} {} {}'. format(elgamalPrivateKey.p,elgamalPrivateKey.g,elgamalPrivateKey.x)}
            else:
                return {'status':'ERROR', 'message':'Error Key from Server is 0'}

    def sendkey_elgamal(self):
        
        if (self.tokenid==""):
            return "Error, not authorized"
        key=generate_keys();
        self.elpublic=key['publicKey']
        self.elprivate=key['privateKey']

        string="sendelgamalkey {} {} {} {} {}\r\n" . format(self.tokenid,self.elpublic.p,self.elpublic.g,self.elpublic.h, self.elprivate.x)
        result = self.sendstring(string)
        if result['status']=='OK':
            return "{}" . format(json.dumps(result['messages']))
        else:
            return {'status':'ERROR', 'message':'Error, {}' . format(result['message'])}
       
        
    def getkey(self, username):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="getkey {} {} \r\n" . format(self.tokenid,username)
        result = self.sendstring(string)
        if result['status']=='OK':
            return {'status':'OK', 'key':result['key']}
        else:
            return {'status':'ERROR', 'message':'Error, {}' . format(result['message'])}
    
   
if __name__=="__main__":
    cc = ChatClient()
    while True:
        cmdline = input("Command {}:" . format(cc.tokenid))
        print(cc.proses(cmdline))

