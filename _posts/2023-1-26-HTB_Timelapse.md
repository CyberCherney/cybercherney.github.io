---
layout: post
title: "HTB: Timelapse"
author: Andrew Cherney
date: 2023-01-26 20:58:03
icon: ""
tags: htb easy-box
post_description: ""
---

<h1>Summary</h1>



<h1>Enumeration</h1>

<h2>rustscan</h2>

```bash
rustscan 10.10.11.152 | tee results.scan
```

_Editors note: this is an old box writeup and I was using a different version of rustscan which is why the default output is different than other writeups on this blog._

```
PORT      STATE SERVICE           REASON          VERSION
53/tcp    open  domain? 
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2022-06-10 09:28:00Z)
135/tcp   open  msrpc Microsoft Windows RPC
139/tcp   open  netbios-ssn Microsoft Windows netbios-ssn
389/tcp   open  ldap Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl? syn-ack ttl 126
5986/tcp  open  ssl/http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf .NET Message Framing
49667/tcp open  msrpc Microsoft Windows RPC
49673/tcp open  ncacn_http Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc Microsoft Windows RPC
49696/tcp open  msrpc Microsoft Windows RPC
55158/tcp open  msrpc Microsoft Windows RPC
```

If we didn't know this was a windows machine already that scan is a shining beacon to indicate so. Now nmap is flagging port 445 as potentially microsoft-ds, but that port is commonly used for file sharing with SMB on Windows. 

<h2>Port 445 - SMB</h2>

Best practice is to list the shares available on the SMB service. 

```bash
┌─[✗]─[raccoon@garbagebin]─[~/_hacking/Hackthebox/.old/Timelapse]
└──╼ $smbclient -L 10.10.11.152
Enter WORKGROUP\raccoon's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Shares          Disk      
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
```

```bash
┌─[raccoon@garbagebin]─[~/_hacking/Hackthebox/.old/Timelapse]
└──╼ $smbclient --no-pass //10.10.11.152/Shares
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 25 10:39:15 2021
  ..                                  D        0  Mon Oct 25 10:39:15 2021
  Dev                                 D        0  Mon Oct 25 14:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 10:48:42 2021

		6367231 blocks of size 4096. 1253777 blocks available
smb: \> cd HelpDesk
smb: \HelpDesk\> ls
  .                                   D        0  Mon Oct 25 10:48:42 2021
  ..                                  D        0  Mon Oct 25 10:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 09:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 09:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 09:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 09:57:44 2021

		6367231 blocks of size 4096. 1251743 blocks available
smb: \HelpDesk\> cd ../Dev
smb: \Dev\> ls
  .                                   D        0  Mon Oct 25 14:40:06 2021
  ..                                  D        0  Mon Oct 25 14:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 10:46:42 2021

		6367231 blocks of size 4096. 1251364 blocks available
smb: \Dev\> get winrm_backup.zip 
```



