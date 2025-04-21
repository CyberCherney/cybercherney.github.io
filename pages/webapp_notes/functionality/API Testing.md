---
title: "API Testing"
layout: notes
tags:
  - webapp
  - methodology
  - api
  - normalization
---
## Summary

While the internet grows and Web Applications gain complexity, there exists a growing need for streamlined and simple actions that can be requested from an endpoint designed for a specific purpose. Handling a bunch of PHP files or JS files can be cumbersome, so APIs were designed as a more modular way to handle functionality within an application, whether frontend or backend. An API can be vulnerable to anything from SQLi to Access Control or Authorization exploits. How an API is exploited depends on its functionality and misconfiguration. To truly find an API vulnerability it is important to understand how it is meant to be used before trying to leverage assumptions and mistakes made by the developers.

## Methodology

When looking for API vulnerabilities ask/try the following:
- [ ] **Are there any APIs found from basic site usage?**
- [ ] **Are there any functions on the front-end that might be interacting with a backend API?**
- [ ] **Is there documentation that can be found for an API?**
	- [ ] `/api /swagger/index.html /openapi.json` are common places
		- [ ] always traverse up the directory structure to find out additional error information
- [ ] **Can you find out what type of API it is?**
	- [ ] RESTful APIs are in a format of `/path/field/param1`, take JSON, parameters, or XML
	- [ ] SOAP is going to require XML for data
	- [ ] OpenAPI can be read with OpenAPI Parser BApp
	- [ ] if not apparent determine the structure and do research/manual testing   
  
<br>
AFTER FINDING AN API
- [ ] discover the entire attack surface
	- [ ] search through documentation
	- [ ] search through JS files for endpoints or APIs
		- [ ] JS Link Finder BApp
	- [ ] create wordlists based on potential functionality of the site
	- [ ] find all endpoints of the API
- [ ] find out how to interact with each endpoint
	- [ ] change the HTTP methods (OPTIONS GET POST PATCH PUT DELETE)
	- [ ] change the data formats of the request (JSON XML encoded parameters)
	- [ ] check for required authentication
	- [ ] check rate limits
- [ ] check if the documentation is lacking
	- [ ] try things the documentation does not specify, does it act as expected
- [ ] **Are there other versions of the API?**
	- [ ] check all functionality on the different version along with previous tests
- [ ] **Are there any fields that could be mass assigned enumerated from the API?**
	- [ ] try to use the API to get additional info about potential fields
	- [ ] check documentation for all fields it might auto-set or use
	- [ ] look for information around accounts that can be used in registration or other exploits
- [ ] **Can a request to a backend API be manipulated?**
	- [ ] try to force an error to give details on the structure
	- [ ] try to access resources you shouldn't have permissions for
	- [ ] try to overwrite existing parameters `/users/search?name=peter&name=carlos`
		- [ ] PHP parses the last parameter `carlos`
		- [ ] ASP.NET combines both yielding an invalid username error `peter,carlos`
		- [ ] Node.js parses the first parameter only `peter`
		- [ ] any parameter could potentially be parameter pollution
	- [ ] try to add directory traversal to test for normalization
		- [ ] `GET /edit_profile.php?name=123` might be `/api/users/123` on the backend
		- [ ] `GET /edit_profile.php?name=123/../admin` might become `/api/users/123/../admin`
		- [ ] if the server normalizes you can enumerate other users or other fields/parameters
			- [ ] look to Directory Traversal for tips on getting past filters
			- [ ] "No Route" means you are out of the API root
			- [ ] openapi.json can be found in the API root
	- [ ] try to check if parameters are being truncated with `#foo` at the end of one
		- [ ] this request `GET /userSearch?name=peter%23foo&back=/home` might turn into `GET /users/search?name=peter#foo&publicProfile=true` on the request to API
		- [ ] url encode symbols for truncating `%26 &  %23 #`
		- [ ] errors could give valuable information on hidden fields 
	- [ ] try to fuzz for potential fields and functions (custom word lists are best)

## Tools/Examples

#### Mitigation

Secure all documentation you don't intend to be publicly accessible  
Ensure documentation is up to date so legit testers can see the whole attack surface  
Apply a whitelist of allowed methods and data types, in addition to properties in requests  
Validate the content type on every request or response  
Use generic error messages  
Protect all API versions not only the current one  
Encode requests prior to using them in an internal or external API  
Verify data is in the expected format and structure  




