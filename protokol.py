from enum import Flag
import sys
import os
import json
import uuid
import logging
from queue import  Queue

class Chat:
	def __init__(self):
		self.sessions={}
		self.users = {}
		self.groups = {}
		self.users['stu']={ 'nama': 'Restu Agung P.', 'negara': 'Argentina', 'password': '1234abcd', 'incoming' : {}, 'outgoing': {}, 'files': {}, 'passwd': {}}
		self.users['ubay']={ 'nama': 'M. Subhan', 'negara': 'Inggris', 'password': '1234abcd', 'incoming': {}, 'outgoing': {}, 'files': {}, 'passwd': {}}
	def proses(self,data):
		j=data.split(" ")
		try:
			command=j[0].strip()
			if (command=='auth'):
				username=j[1].strip()
				password=j[2].strip()
				logging.warning("AUTH: auth {} {}" . format(username,password))
				return self.autentikasi_user(username,password)
			elif (command=='send'):
				sessionid = j[1].strip()
				usernameto = j[2].strip()
				message=""
				for w in j[3:]:
					message="{} {}" . format(message,w)
				usernamefrom = self.sessions[sessionid]['username']
				logging.warning("SEND: session {} send message from {} to {}" . format(sessionid, usernamefrom,usernameto))
				return self.send_message(sessionid,usernamefrom,usernameto,message)
			elif (command=='send_file_aes'):
				sessionid = j[1].strip()
				usernameto = j[2].strip()
				filename = j[3].strip()
				key = j[4].strip()
				message=""
				for w in j[5:-1]:
					message="{}{}" . format(message,w)
				usernamefrom = self.sessions[sessionid]['username']
				logging.warning("SEND: session {} send file {} from {} to {} with data {}" . format(sessionid, filename, usernamefrom, usernameto, message))
				return self.send_file_aes(sessionid,usernamefrom,usernameto,filename,key,message)
			elif (command=='send_file_3des'):
				sessionid = j[1].strip()
				usernameto = j[2].strip()
				filename = j[3].strip()
				key = j[4].strip()
				message=""
				for w in j[5:-1]:
					message="{}{}" . format(message,w)
				usernamefrom = self.sessions[sessionid]['username']
				logging.warning("SEND: session {} send file {} from {} to {} with data {}" . format(sessionid, filename, usernamefrom, usernameto, message))
				return self.send_file_3des(sessionid,usernamefrom,usernameto,filename,key,message)
			elif (command=='my_file'):
				sessionid = j[1].strip()
				logging.warning("FILES: session {}" . format(sessionid))
				username = self.sessions[sessionid]['username']
				return self.my_file(sessionid, username)
			elif (command=='download_file_aes'):
				sessionid = j[1].strip()
				usernameto = j[2].strip()
				filename = j[3].strip()
				key = j[4].strip()
				logging.warning("DOWNLOAD: session {} file {}" . format(sessionid, filename))
				username = self.sessions[sessionid]['username']
				return self.download_file_aes(sessionid, username, usernameto, filename,key)
			elif (command=='download_file_3des'):
				sessionid = j[1].strip()
				usernameto = j[2].strip()
				filename = j[3].strip()
				key = j[4].strip()
				logging.warning("DOWNLOAD: session {} file {}" . format(sessionid, filename))
				username = self.sessions[sessionid]['username']
				return self.download_file_3des(sessionid, username, usernameto, filename,key)
			elif (command=='sendkey'):
				sessionid = j[1].strip()
				key = j[2].strip()
				logging.warning("SEND KEY: session {} key {}" . format(sessionid, key))
				username = self.sessions[sessionid]['username']
				return self.sendkey(sessionid, username, key)
			elif (command=='getkey'):
				sessionid = j[1].strip()
				usernameto = j[2].strip()
				logging.warning("GET KEY: session {} username {}" . format(sessionid, usernameto))
				return self.getkey(sessionid, usernameto)
			else:
				return {'status': 'ERROR', 'message': '**Protocol Tidak Benar'}
		except KeyError:
			return { 'status': 'ERROR', 'message' : 'Informasi tidak ditemukan'}
		except IndexError:
			return {'status': 'ERROR', 'message': '--Protocol Tidak Benar'}
	def autentikasi_user(self,username,password):
		if (username not in self.users):
			return { 'status': 'ERROR', 'message': 'User Tidak Ada' }
		if (self.users[username]['password']!= password):
			return { 'status': 'ERROR', 'message': 'Password Salah' }
		tokenid = str(uuid.uuid4()) 
		self.sessions[tokenid]={ 'username': username, 'userdetail':self.users[username]}
		return { 'status': 'OK', 'tokenid': tokenid }
	def get_user(self,username):
		if (username not in self.users):
			return False
		return self.users[username]
	
	def send_message(self,sessionid,username_from,username_dest,message):
		if (sessionid not in self.sessions):
			return {'status': 'ERROR', 'message': 'Session Tidak Ditemukan'}
		s_fr = self.get_user(username_from)
		s_to = self.get_user(username_dest)
		
		if (s_fr==False or s_to==False):
			return {'status': 'ERROR', 'message': 'User Tidak Ditemukan'}

		message = { 'msg_from': s_fr['nama'], 'msg_to': s_to['nama'], 'msg': message }
		outqueue_sender = s_fr['outgoing']
		inqueue_receiver = s_to['incoming']
		try:	
			outqueue_sender[username_from].put(message)
		except KeyError:
			outqueue_sender[username_from]=Queue()
			outqueue_sender[username_from].put(message)
		try:
			inqueue_receiver[username_from].put(message)
		except KeyError:
			inqueue_receiver[username_from]=Queue()
			inqueue_receiver[username_from].put(message)
		return {'status': 'OK', 'message': 'Message Sent'}
	
	def send_file_aes(self, sessionid, username_from, username_dest, filename,key, message):
		if (sessionid not in self.sessions):
			return {'status': 'ERROR', 'message': 'Session Tidak Ditemukan'}
		s_fr = self.get_user(username_from)
		s_to = self.get_user(username_dest)
		if (s_fr==False or s_to==False):
			return {'status': 'ERROR', 'message': 'User Tidak Ditemukan'}

		try : 
			s_to['passwd'][username_from][filename] = key
		except KeyError:
			s_to['passwd'][username_from] = {}
			s_to['passwd'][username_from][filename] = key
		
		try : 
			s_to['files'][username_from][filename] = message
		except KeyError:
			s_to['files'][username_from] = {}
			s_to['files'][username_from][filename] = message

		try : 
			s_fr['files'][username_dest][filename] = message
		except KeyError:
			s_fr['files'][username_dest] = {}
			s_fr['files'][username_dest][filename] = message

		return {'status': 'OK', 'message': 'File Sent'}
	
	def send_file_3des(self, sessionid, username_from, username_dest, filename,key, message):
		if (sessionid not in self.sessions):
			return {'status': 'ERROR', 'message': 'Session Tidak Ditemukan'}
		s_fr = self.get_user(username_from)
		s_to = self.get_user(username_dest)
		if (s_fr==False or s_to==False):
			return {'status': 'ERROR', 'message': 'User Tidak Ditemukan'}

		try : 
			s_to['passwd'][username_from][filename] = key
		except KeyError:
			s_to['passwd'][username_from] = {}
			s_to['passwd'][username_from][filename] = key
		
		try : 
			s_to['files'][username_from][filename] = message
		except KeyError:
			s_to['files'][username_from] = {}
			s_to['files'][username_from][filename] = message

		try : 
			s_fr['files'][username_dest][filename] = message
		except KeyError:
			s_fr['files'][username_dest] = {}
			s_fr['files'][username_dest][filename] = message

		return {'status': 'OK', 'message': 'File Sent'}
	def my_file(self, sessionid, username):
		if (sessionid not in self.sessions):
			return {'status': 'ERROR', 'message': 'Session Tidak Ditemukan'}
		s_usr = self.get_user(username)
		files = s_usr['files']
		msgs = {}
		for user in files:
			msgs[user] = []
			for file in files[user] :
				msgs[user].append(file)
		return {'status': 'OK', 'messages': msgs}
	def download_file_aes(self, sessionid, username, usernameto, filename,key):
		if (sessionid not in self.sessions):
			return {'status': 'ERROR', 'message': 'Session Tidak Ditemukan'}
		s_usr = self.get_user(username)
		if(usernameto not in s_usr['files']):
			return {'status': 'ERROR', 'message': 'File Tidak Ditemukan'}
		if filename not in s_usr['files'][usernameto]:
			return {'status': 'ERROR', 'message': 'File Tidak Ditemukan'}
		data = s_usr['files'][usernameto][filename]
		gkey=s_usr['passwd'][usernameto][filename]
		# if key==gkey:
		return {'status': 'OK', 'messages': f'Downloaded {gkey}', 'filename':f'{filename}', 'data':f'{data}'}
	def download_file_3des(self, sessionid, username, usernameto, filename,key):
		if (sessionid not in self.sessions):
			return {'status': 'ERROR', 'message': 'Session Tidak Ditemukan'}
		s_usr = self.get_user(username)
		if(usernameto not in s_usr['files']):
			return {'status': 'ERROR', 'message': 'File Tidak Ditemukan'}
		if filename not in s_usr['files'][usernameto]:
			return {'status': 'ERROR', 'message': 'File Tidak Ditemukan'}
		data = s_usr['files'][usernameto][filename]
		gkey=s_usr['passwd'][usernameto][filename]
		# if key==gkey:
		return {'status': 'OK', 'messages': f'Downloaded {gkey}', 'filename':f'{filename}', 'data':f'{data}'}

	def sendkey(self, sessionid, username, key):
		if (sessionid not in self.sessions):
			return {'status': 'ERROR', 'message': 'Session Tidak Ditemukan'}
		self.users[username]['key'] = key
		return {'status': 'OK', 'messages': f'Key Received {key}'}
	def getkey(self, sessionid, username):
		if (sessionid not in self.sessions):
			return {'status': 'ERROR', 'message': 'Session Tidak Ditemukan'}
		if('key' not in self.users[username]):
			return {'status': 'ERROR', 'message': 'Key Tidak Ditemukan'}
		else:
			return {'status': 'OK', 'message': 'Key Ditemukan', 'key':self.users[username]['key']}


# if __name__=="__main__":
	# j = Chat()
	# sesi = j.proses("auth messi surabaya")
	# print(sesi)
	# #sesi = j.autentikasi_user('messi','surabaya')
	# #print sesi
	# tokenid = sesi['tokenid']
	# print(j.proses("send {} henderson hello gimana kabarnya son " . format(tokenid)))
	# print(j.proses("send {} messi hello gimana kabarnya mess " . format(tokenid)))

	














