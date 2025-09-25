import sys
import socket
import re
from datetime import datetime

#Define out target
if len(sys.argv) == 2:  #checking the number of argumensts(2nd arg - ip)
    arg = sys.argv[1]
    pattern = re.compile(r"^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$") #Regex for validating an IP address
    if pattern.match(arg):  #if the argument is an IP address
        target = socket.gethostbyname(arg) #Translate hostname to ipv4
else:
    print("Invalid amount of arguments.")
    print("Syntax: python scanner.py <ip>")
    
#Add a pretty banner
print("-"*50)
print("Scanning target "+target)
print("Time started: "+str(datetime.now()))
print("-"*50)

try:
    for port in range (50, 85):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)  #so just when a port not respond, it skips that one
        result = s.connect_ex((target, port))
        if result == 0:
            print(f"Port {port} is open")
        else:
            print(f"Port {port} is closed")    
        s.close()  #close the socket after checking the port
        
except KeyboardInterrupt:
    print("\nExiting program.")
    sys.exit()
    
except socket.gaierror:
    print("Hostname could not be resolved.")
    sys.exit()
    
except socket.error:
    print("Could not connect to the server")
    sys.exit()                    

print("-"*50)
print("Scanning completed.")
print("Time finished: "+str(datetime.now()))
print("-"*50)
