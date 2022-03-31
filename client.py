import base64
import logging
import socket
import os
import json
from DiffieHellman import DiffieHellman
from aes import AESCipher

diffieHelman = DiffieHellman()

AESDict = {}

TARGET_IP = "167.172.77.139"
TARGET_PORT = 8889

# cipher = AESCipher("ini key", True)

class ChatClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = (TARGET_IP,TARGET_PORT)
        self.sock.connect(self.server_address)
        self.username=""
        self.tokenid=""
    def proses(self,cmdline):
        j=cmdline.split(" ")
        try:
            command=j[0].strip()
            if (command=='auth'):
                username=j[1].strip()
                password=j[2].strip()
                response = self.login(username,password)
                return response
            elif (command=='send_file_aes'):
                usernameto = j[1].strip()
                filename = j[2].strip()
                key = j[3].strip()
                return self.sendfile_aes(usernameto,filename,key)
            elif (command=='my_file'):
                return self.myfile()
            elif (command=='download_file'):
                username = j[1].strip()
                filename = j[2].strip()
                key = j[3].strip()
                return self.downloadfile(username, filename, key)
            elif (command=='download_only'):
                username = j[1].strip()
                filename = j[2].strip()
                # key = j[3].strip()
                return self.downloadfileonly(username, filename)
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
        buffer = file.read()
        cipher = AESCipher(key, True)
        encrypted_buffer = cipher.encrypt_byte(buffer)
        encrypted_file = open(filename+".aes", "wb")
        encrypted_file.write(encrypted_buffer)
        file.close()
        encrypted_file.close()
        buffer_string = base64.b64encode(encrypted_buffer).decode('utf-8')
        message="send_file {} {} {} {} \r\n" .format(self.tokenid, usernameto, filename,key, buffer_string)
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
    
    def downloadfile(self, username, filename,key):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="download_file {} {} {} \r\n" . format(self.tokenid, username, filename)
        result = self.sendstring(string)
        if result['status']=='OK':
            cipher = AESCipher(key, True)
            output_file = open(result['filename'], 'wb')
            decrypted_buffer = cipher.decrypt_byte(base64.b64decode(result['data']))
            output_file.write(decrypted_buffer)
            output_file.close()
            return {'status' : 'OK', 'message':'file {} downloaded' . format(filename)}
        else:
            return {'status':'ERROR', 'message':'Error, {}' . format(result['message'])}
    
    def downloadfileonly(self, username, filename):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="download_file {} {} {} \r\n" . format(self.tokenid, username, filename)
        result = self.sendstring(string)
        if result['status']=='OK':
            output_file = open(result['filename'], 'wb')
            # decrypted_buffer = cipher.decrypt_byte(base64.b64decode(result['data']))
            output_file.write(base64.b64decode(result['data']))
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

