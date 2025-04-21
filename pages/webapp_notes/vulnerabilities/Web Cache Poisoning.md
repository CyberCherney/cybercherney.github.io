---
title: "Web Cache Poisoning"
layout: notes
tags:
  - webapp
  - methodology
  - webcache-poisoning
---
## Summary

Within web applications there exists a demand for web pages being served to a user. These pages might be frequently visited pages that do not warrant contacting the origin server, a home page for example. Instead of the origin server handling each request itself web applications typically have a web cache to store commonly viewed pages. To determine if a page should be cached, a web cache defines a set of cache keys as varying headers, parameters, cookies, request methods, and even URL endpoints. To determine if a page should be served from the cache it will check the stored cache key to the new request's cache key, if they are the same it will serve from the cache, if not it will grab the response from the origin server and store that response in the cache. Some resources cannot be stored in caches such as dynamic pages, so login dashboards or profile pages are generally not vulnerable. If you want to learn about when they are vulnerable head to Web Cache Deception.

Since each stored response is based off a cache key of parameters and headers, it is possible to add an unkeyed parameter that changes some element on the page that does not influence the cache key. This malicious request can get a malicious response stored in the cache, poisoning it. If there are parameters or headers that can influence a pages functionality or even allow for exploits, it is always worth checking for cache poisoning possibilities. 

To properly exploit a Web Cache Poisoning attack it is crucial to identify the cache keys and some parameter or header that can be used as a cache buster, a temporary cache key hitter that will allow you to test around without affecting the average user. Once there identify anything that might allow you to change data on a page or modify requests made to other parts of a site. It is worth noting that poorly testing web caches can make one's pentesting or bug bounty career rather short in the same way negligent testing of SSTI, RCE, SQLi, and Prototype Pollution can. These vulnerabilities have the possibility to drastically alter how a site functions for the end user, and can easily crash or cause errors that affect business uptime. And lastly, the impact of the vulnerability is based solely on how popular or important the page you can poison is. 

## Methodology

**WARNING**: Poisoning a cache without a cache buster can dramatically impact business uptime. Always find a cache buster prior to testing and never execute a found vulnerability on a regular un-cache bustered page.

When looking for Web Cache Poisoning vulnerabilities ask/try the following:
- [ ] **What is the tech stack of the web application?**
	- [ ] try to dig through documentation on ways to leak cache related info per the technology used
- [ ] **Am I getting any web cache responses like `Cache-Control` `Age` or `Vary`**
	- [ ] `Vary` will tell you what headers are specifically cache keys
	- [ ] `Cache-Control` can tell you notable info about the cache
		- [ ] [https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control)
	- [ ] `Age` will let you know how long to wait before poisoning a cache
	- [ ] **Is there a notable time difference between responses?**
- [ ] **Is there a cache buster you can find?**
	- [ ] try a simple `?cb=1`
	- [ ] try removing/modifying the `Accept-Encoding` header
- [ ] **Can you identify the cache keys?**
	- [ ] try removing and adding random parameters to see if the cache does or doesn't store the response
	- [ ] **Are there any unkeyed inputs?**
	- [ ] **Is the cache filtering out query strings or parameters?**
		- [ ] be on the lookout for a keyed element that might be filtered out of the response once cached
- [ ] **Is there any parameter or header that allows modifying a page?**
	- [ ] **Are there any cookies that modify the page?**
	- [ ] **Is there any exploitable gadget to chain with the cache poisoning?**
- [ ] try running Param Miner Burp Addon to get accepted headers (remember to add cache busters)
- [ ] try forcing a 302 redirect with `X-Forwarded-Scheme` or `X-Forwarded-Proto`
	- [ ] if successful try finding another header to modify the page such as `X-Forwarded-Host`
- [ ] try looking at loaded javascript files for potential parameters
- [ ] try adding a port to the `Host` header
	- [ ] if successful try to pop an XSS or cause a DoS with a cache buster
- [ ] **Is the cache normalizing any keyed inputs?**
	- [ ] Apache: `GET //   ` Nginx: `GET /%2F   ` PHP: `GET /index.php/xyz   ` .NET: `GET /(A(xyz)/`
	- [ ] can you get `/<script>X</script>/../../home` to normalize to `/home` somehow
- [ ] try adding UTM parameters https://en.wikipedia.org/wiki/UTM_parameters
	- [ ] `?utm_content=buffercf3b2&utm_medium=social&utm_source=snapchat.com&utm_campaign=buffer`
- [ ] try cloaking a parameter with a second `?` or a duplicate with a delimiter after an unkeyed parameter
	- [ ] aka `?normal=aaa?exploit=xss` or `?normal=aaa&unkeyed=bbb;normal=xss`
- [ ] try a fat GET request with a different body than a parameter
	- [ ] try forcing it into a POST method with `X-HTTP-Method-Override: POST`
- [ ] try messing with a CSS file without a doctype specified to get a server error
- [ ] **Is there any way to manipulate the cache key?**
	- [ ] sometimes delimiters can be added to cause two different requests to have the same cache key
- [ ] **Is there some internal cache?**
	- [ ] hard to determine, but if there are elements of multiple requests you have sent it is an internal cache
	- [ ] check other pages you have not tested on for influence of your tests
- [ ] **Can you get the page to load data from a site you control?**

## Tools/Examples

Potential cache busters
```
Accept-Encoding: gzip, deflate, cachebuster 
Accept: */*, text/cachebuster 
Cookie: cachebuster=1 
Origin: https://cachebuster.vulnerable-website.com
```

#### Mitigation

Disable caching if it isn't necessary  
Restrict to static responses  
Fully research and understand the 3rd party services you use  
Disabling headers that are default by your CDN  
Rewrite requests if something is being excluded from the cache key  
Don't accept fat GET requests  
Patch client-side vulns  



