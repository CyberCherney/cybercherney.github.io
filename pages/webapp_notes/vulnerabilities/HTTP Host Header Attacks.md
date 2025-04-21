---
title: "HTTP Host Headers Attacks"
layout: notes
tags:
  - webapp
  - methodology
  - host-header
  - FI_http-headers
  - Co_ssrf
  - Co_xss
  - Co_sqli
---
## Summary

Within any request exists a Host header to denote the intended target of the request. In most applications this header will merely point to a domain which will serve requests, but in some this Host header is interacted with and used in different ways. Attempting to access localhost or an internal IP address could allow you to view and interact with a resource intended for internal users permitting it uses the same load balancer/reverse proxy/server as the webapp in question. Abusing a Host header is an exercise in creativity after learning how the application uses it. 

Application logic sometimes allows for multiple Host headers or different types of Host headers to overwrite or designate different Hosts for the front end and back end. It is possible that the port within the header is not validated and can be used to smuggle payloads. A domain ending in the same domain in question might allow a redirect to a host you control. An absolute url could allow for arbitrarily defining the Host header. Depending on how the applicating uses the Host header it can be used to perform SQLi - MySQL Injection, XSS - JavaScript Injection, or even add our own domains to change application functionality. 

## Methodology

When looking for Host Header Vulnerabilities check/ask the following:
- [ ] **Can I change the header without an error?**
	- [ ] if invalid host header likely not vulnerable
- [ ] **Is any change I make reflected to any page?**
	- [ ] check what page reflects the Host and possible implications of where you see it
		- [ ] password reset links or script references in html are gold mines if found
- [ ] check how it handles a deliberately improper host
- [ ] try to access localhost or internal IPs
- [ ] try to pass a port, then follow that up with a string in the port slot
	- [ ] if the port is not validated it might be able to be combo'd with another vuln
- [ ] check if it will accept a domain ending in the domain name (agoogle.com for google.com)
- [ ] try duplicate headers
- [ ] try absolute url with malicious host
- [ ] try an indent or space between two hosts on the same line (line wrapping)
- [ ] try override Host headers:
		`X-Host` `X-Forwarded-Server` `X-Forwarded-Host` `X-Forwarded-For` `X-HTTP-Host_Override` `Forwarded` `X-Client-IP` `X-Remote-IP` `X-Remote-Addr`
- [ ] check for SQL injection in case of logging Host to a database
- [ ] try to scan for internal subdomains through Host
- [ ] if you can set a malicious Host, try to poison the cache of a page
- [ ] try to make malformed requests
	- [ ] [https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface)
	- [ ] try @ instead of / for a login attempt at a backend service

## Capabilities

SQLi  
XSS  
SSRF  

## Found In

HTTP Headers  

## Tools/Examples

param miner can be used to probe for all supported headers assuming you have a server to call to
burp can send grouped requests in conjunction if connection-states can be abused






