---
title: "CSRF"
layout: notes
tags:
  - webapp
  - methodology
  - csrf
  - Co_csrf
  - FI_user-input
---
## Summary

CSRF at its core is attempting to get an application to perform some action at the behest of an attacker controlled domain. The user is often unaware of the underlying executing JavaScript and merely requires the user visit an attacker owned link. Sending requests in this way can bypass some Same Origin Policy (SOP) protections and is only limited by what the application is capable of. 

When looking to exploit CSRF it is important to find functions that would warrant control of, such as changing user permissions or user data. Then there must be some session cookie as other forms of authorization prevent CSRF. And finally the parameters and fields must be predictable. 

Although XSS - JavaScript Injection and CSRF - Cross-Site Request Forgery both end up executing JavaScript, Cross-Site Scripting can be stored on the vulnerable web application, lending to far more dangerous attacks and more sophisticated scripts. CSRF in a way is a one way exploit where you control the request and nothing else. It can be exploited by bypassing token validation, SameSite restrictions, and referrer based defenses.

## Methodology

When looking for CSRF vulnerabilities ask/try the following:
- [ ] **Is there any function worth making another user perform?**
- [ ] **Does this function have a CSRF token?**
	- [ ] try changing method to GET without the token
	- [ ] try removing the token
	- [ ] try submitting one user's csrf token for another
	- [ ] try submitting another form's csrf for a different one
	- [ ] **Is the csrf token in a cookie?**
		- [ ] check if the csrf token is reflected within the cookie
			- [ ] if yes change both to something arbitrary
		- [ ] try removing the cookie
		- [ ] try an invalid cookie
		- [ ] submit a cookie from another user
			- [ ] add submitting a token from another user if successful
		- [ ] **Is there a place to set cookies?**
			- [ ] check subdomains for functionality
			- [ ] if url-based try appending `%0d%0aSet-Cookie:%20csrfKey=asdasd%3b%20SameSite=None`
- [ ] **Are SameSite restrictions set?**
	- [ ] Is it Strict?
		- [ ] probably nothing here
	- [ ] Is it Lax (chrome default*)?
		- [ ] try changing the request method to GET
			- [ ] `_method` can be used in some frameworks
				- [ ] `<input type="hidden" name="_method" value="GET">`
			- [ ] within a url can use a GET request with `_method=POST`
			- [ ] try to override with `X-Http-Method-Override: GET`
		- [ ] **Are there any subdomains or gadgets that craft requests for me?**
			- [ ] check WebSocket for potential vulnerabilities
				- [ ] change `Origin` on handshake and try CSRF from there
		- [ ] check if Lax is specifically set or if it is set by browser
			- [ ] if not set deliberately there is a 120 second window after cookie creation where its vulnerable
				- [ ] specifically the restrictions of being a POST and from a top-level domain don't exist
				- [ ] use `window.onclick` or `window.open` to refresh cookie on a page
	- [ ] Is it None (must have the Secure attribute)?
		- [ ] investigate further for any possible use
- [ ] **Are there referer header based protections?**
	- [ ] try removing the header entirely
	- [ ] try appending a malicious domain with ?
	- [ ] for CSRF make sure the `Referrer-Policy: unsafe-url` header exists
		- [ ] use `history.pushState('', '', '/?URL')` adds a url to the history for referrer

## Capabilities

Request Forgery  
Replicating User Actions  

## Found In

User Input  

## Tools/Examples

[https://csrfshark.github.io/app/](https://csrfshark.github.io/app/)
simple email changing request
```
<html>
    <body>
        <form action="https://vulnerable-website.com/email/change" method="POST">
            <input type="hidden" name="email" value="pwned@evil-user.net" />
        </form>
        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```

window opening on user click w/o leaving page
```
window.onclick = () => { window.open('https://vulnerable-website.com/login/sso'); }
```

#### Mitigations

CSRF tokens for forms  
High entropy, tied to a session, and validated in every case before execution  
Store server side in user data, then validate against, if failed to validate reject request  
SameSite cookies to prevent other sites using cookies in a request  
`SameSite: Strict`, lower to Lax if there is a good reason, steer clear of None  
Referer-based validation to make sure the request is from the application's domain  




