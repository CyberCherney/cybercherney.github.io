---
title: "Web Cache Deception"
layout: notes
tags:
  - webapp
  - methodology
  - webcache-deception
---
## Summary

The web is fundamentally run by the relationship between caching servers and origin servers. These two servers have the potential to interpret information in different ways. For example an Apache web server might read a URL different to CloudFlare's caching server. These discrepancies are where the vulnerability come into play. By abusing the difference in how a caching server and an origin server read URLs it is possible to cache dynamic pages that would otherwise never be cached. Then these cached dynamic pages can be visited without the necessary authorization it would normally require. 

Caching a response is a somewhat complicated endeavor. First the cache must have a cache key that is unique and uncached, which consists of the URL path, query parameters, method type (GET HEAD OPTIONS), and more. If the requested resource is not already cached it will check if the response should be cached.  Servers will look at rules including the file extensions, the directory, the file name, and other custom defined rules. If the URL of the request matches the rules to be cached it will retrieve a response from the origin server and cache that result. When there is a difference in how that URL is parsed between the two servers it can cache unintended data at the requested endpoint. 

This then brings us to the exploit itself. If there is a discrepancy to be found it will be one of 3 possibilities: mapping URLs, processing delimiter characters, and normalizing paths. With a solid understanding of these discrepancies it is possible to deceive the web cache, or even achieve Web Cache Poisoning.

## Methodology

When looking for Web Cache Deception vulnerabilities ask/try the following:
- [ ] **Is there any endpoint that returns sensitive data?**
	- [ ] **Is this data from a GET, HEAD, or OPTIONS method?**
- [ ] **Am I getting any indication of what is being cached?**
	- [ ] **Are there large differences in response time for duplicate requests?**
	- [ ] check `X-Cache` for hit and miss
		- [ ] dynamic is not abusable, refresh means revalidate
- [ ] **Is the website using traditional or RESTful URL mapping?**
	- [ ] try `http://example.com/path/file.html` for traditional
	- [ ] try `http://example.com/path/param1/param2` for RESTful
- [ ] **Is there a load balancer in addition to the caching server?**
	- [ ] if there is one any encoded character may need to be entirely encoded again `%23 --> %25%32%33`
- [ ] try forcing a deliberate error `/profileaaa`
- [ ] try adding an arbitrary path segment `/profile/TEST`
- [ ] try adding a file extension `/profile/wcd.js`
- [ ] try adding a delimiter `/profile;aaa`
	- [ ] intruder with the list or try known based off framework, might need to urlencode
- [ ] try Directory Traversal for static path mapping `/static/../profile`
- [ ] **Is my request being normalized?**
	- [ ] try normalization to determine which server is normalizing:
		- [ ] ORIGIN SERVER NORMALIZATION
			- [ ] try `/static/..%2f/profile`
		- [ ] CACHE SERVER NORMALIZATION
			- [ ] using a delimiter you can get the cache to read the whole request and the origin only part
			- [ ] try `/profile;%2f%2e%2e%2fstatic` and URL encode delimiter if not working
		- [ ] if successful try GETing common files with normalization such as `robots.txt`
- [ ] check if common files are being cached

## Tools/Examples

can set dynamic cache buster with Param Miner
IIS is particularly vulnerable as `\` is not interpreted in many web cachers

origin server delimiters by framework
```
Java frameworks (includes Spring): ;
Ruby on Rails: .
OpenLiteSpeed: %00
Nginx: %0a
Gunicorn, Puma: #
```

normalization by server
```
CloudFlare: /hello/..%2Fworld
CloudFront: /world
GCP: /hello/..%2Fworld
Azure: /world
Imperva: /world
Fastly: /hello/..%2Fworld
Apache: /hello/..%2Fworld
NginX: /world
IIS: /world
Gunicorn: /hello/..%2Fworld
OpenLite: /world
Puma: /hello/..%2Fworld
```

common static directories
```
/static
/assets
/wp-content
/media
/templates
/public
/shared
```

common file extensions
```
js
css
docx
ico
```

common specific filenames
```
robots.txt
favicon.ico
```

#### delimiters
```
;
!
"
#
$
%
&
'
(
)
*
+
,
-
.
/
:
;
<
=
>
?
@
[
\
]
^
_
`
{
|
}
~
%21
%22
%23
%24
%25
%26
%27
%28
%29
%2A
%2B
%2C
%2D
%2E
%2F
%3A
%3B
%3C
%3D
%3E
%3F
%40
%5B
%5C
%5D
%5E
%5F
%60
%7B
%7C
%7D
%7E
%00
%0A
%09
```

#### Mitigation

Use `Cache-Control` to mark dynamic resources
- Set `no-store` and `private` 
Configure CDN so caching rules don't override `Cache-Control`
Enable any protection from CDN for cache deception attacks
Verify the origin and caching interpret URL paths (normalize) the same



