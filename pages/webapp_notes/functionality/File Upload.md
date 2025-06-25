---
title: "File Upload"
layout: notes
tags:
  - webapp
  - methodology
  - file-upload
---
## Summary

Applications for many reasons might want to give users the ability to upload files. Without the proper protections unfettered file uploads can turn into direct code execution leading to further sensitive information disclosure, account takeovers, or even flat out source code leakage depending on the environment. Whenever an image upload portal or resume upload button is seen these are testing grounds to determine if there is a way to bypass upload restrictions and what harm can be done if bypassed.  

## Methodology

When looking for File Upload vulnerabilities ask/try the following:
- [ ] **Are any extensions being filtered?**
- [ ] **Is any content being used?**
- [ ] try changing the `Content-Type`
- [ ] check what extensions are allowed
	- [ ] check what extensions are truly allowed by fuzzing
	- [ ] check what data types are allowed in upload
	- [ ] try to obfuscate extensions with capitalization (pHp)
	- [ ] try changing the extension in the request
	- [ ] try providing multiple extensions (file.png.php)
	- [ ] try escaping the required extension with %00 or ; or another method depending on backend tech
	- [ ] try to URL encode . with %2E
		- [ ] depending on parsing add multubyte unicode characters 
		- [ ] `xC0 x2E`, `xC4 xAE` or `xC0 xAE` translate to `x2E` if parsed as UTF-8
	- [ ] if the application is stripping extensions try to nest them (file.p.phphp)
	- [ ] if svg is allowed in a png upload try to get XSS working
- [ ] can you access other account's uploads based on URL structure or guessing
- [ ] check if the application renames the file
- [ ] check if you can change the filename within the request
	- [ ] try absolute directories in the filename of the request to change upload directory
	- [ ] try Directory Traversal in the filename of the request
	- [ ] check if .htaccess can be uploaded to change execution functionality
- [ ] **Are there any size restrictions on the file?**
	- [ ] try uploading a large file to check for DoS potential
- [ ] try to add a trailing character such as . to test functionality
- [ ] if the upload restricts to only images/gifs
	- [ ] add magic bytes at top for the "expected" filetypes `FF D8 FF` for jpg then add php
	- [ ] use exiftool to insert payloads
- [ ] if the application temporarily stores the file
	- [ ] try to use a race condition to execute in the small window it exists
	- [ ] try to determine if the name is random or predictable
	- [ ] try to send in parallel in repeater of burp
- [ ] if the file upload is zip
	- [ ] try to create and upload a symlink within the zip
- [ ] try PUT on non-standard locations for upload without script (can check with OPTIONS prior)

## Potential Impact

Remote Code Execution  
Data Leakage  
Server Compromise  

## Tools/Examples

[https://github.com/synacktiv/astrolock](https://github.com/synacktiv/astrolock)

[https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there.html](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there.html)

[https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html#file-upload](https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html#file-upload)

basic command run
```
\<?php echo system($_GET['command']); ?\>
```

exiftool (needs to be .php extension)
```
exiftool -comment="<?php phpinfo(); ?>" nasa.png
```

symlink zip upload
```
ln -s ../../../../../../../../../../../var/www/html/shop/functions.php functions.pdf
zip -r --symlinks functions.zip functions.pdf
```
#### php ext
```
php
php2
php3
php4
php5
php6
php7
phps
phps
pht
phtm
phtml
pgif
shtml
htaccess
phar
inc
hphp
ctp
module
```


#### Mitigation

USE AN ESTABLISHED FRAMEWORK FOR PREPROCESSING  

Don't upload files to the permanent filesystem until validated  
Same-origin-policy can help protect you  
Filenames shouldn't come from users, if they control extension that's even worse  
Whitelist mime types for display, others will download  
Remove exif data and chunks from PNGs  