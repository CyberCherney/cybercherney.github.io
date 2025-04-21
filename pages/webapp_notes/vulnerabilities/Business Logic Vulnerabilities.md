---
title: "Business Logic Vulnerabilities"
layout: notes
tags:
  - webapp
  - methodology
  - business_logic
---
## Summary

Applications like any other script or process have to be developed by humans or at least by an AI trained on human code. Those humans can be on multiple teams working in tandem to create a larger application which has varied functionality. Within that coordination step there are assumptions that can be made by each team of the development process.  Those assumptions are what causes most of the business logic vulnerabilities that can be found. 

There may be an assumption that a user after successfully providing credentials upon login will not change the username associated within the 2FA request. There may be an assumption where a user will not add items to a card between POSTing checkout and GETing the confirmation page. These issues are dependent on the specific application you are looking at and finding them takes an understanding of the purpose of the application along with how information is handled at every step during each process. 

These flaws are emblematic of a larger design problem within applications and once found can be used to predict and find other mishandling of processes within the application.

## Methodology

When looking for business logic vulnerabilities, be sure to check/ask the following:
- [ ] **What assumptions are made?**
- [ ] **How is the information I provide processed?**
- [ ] For request data fields:
	- [ ] try an extremely long string
	- [ ] try no string
	- [ ] try null values
	- [ ] try booleans
	- [ ] change data type
- [ ] For parameters:
	- [ ] try adding additional parameters
		- [ ] best if they exist in other steps
	- [ ] remove parameters
	- [ ] modify parameters
- [ ] For endpoints:
	- [ ] try to access endpoints in different orders than expected
	- [ ] try to access endpoints multiple times after completing further steps in the process
	- [ ] try dropping requests/omitting steps in a process then continuing on
- [ ] For data in general:
	- [ ] check where encryption takes place and if any values are reflected back to you
	- [ ] try to determine the backend tech processing the data being provided
- [ ] For emails:
	- [ ] try to determine if you can parse data within the email and still get emails sent to you
	- [ ] [https://portswigger.net/research/splitting-the-email-atom#generating-email-splitting-attacks](https://portswigger.net/research/splitting-the-email-atom#generating-email-splitting-attacks)








