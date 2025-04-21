---
title: "SSTI"
layout: notes
tags:
  - webapp
  - methodology
  - ssti
  - FI_user-input
  - Co_reading-files
  - Co_sensitive-info-disclosure
  - Co_rce
---
## Summary

Server Side Template Injection is an abuse of dynamic webapp rendering engines which take templates to display or render differing data depending on the context. Some sites might foolishly offer functionality of using templates to users without understanding the true danger. In short, SSTI can be used to run remote code, read files, download remote files, and even escape sandboxes given the right context/language/templating engine. 

This vulnerability can appear in both plaintext contexts, where the result is reflected back to the user directly, or in code contexts, where the user input is placed within a template expression and we can escape that template to inject another. Both involve fuzzing for the templating engine being used, and then further research and experimentation to determine the true danger within the present environment.

{% raw %}
## Methodology

**WARNING**: SSTI can seriously mess up applications, be sure your payloads are minimal impact during hunting.

When looking for SSTI ask/try the following:
- [ ] **Is there a templating engine being used?**
	- [ ] can I find out what that engine is prior to enumeration
- [ ] **Are there any places where my input is reflected back to me?**
	- [ ] if yes plaintext context SSTI payloads
	- [ ] try a simple polyglot string to get an error: `${{<\%[%'"}}%\`
- [ ] **Are there any places using variables that will be processed by a template?**
	- [ ] if yes code context SSTI payloads
	- [ ] try adding `}}<tag>` to see if the referenced variable carries the tag
- [ ] try testing to find the templating engine through an error or fuzzing
	- [ ] mark down any files explicitly mentioned in the error messages
	- [ ] read syntax of discovered engine
		- [ ] check for a security tab or warnings within documentation

<br>
ONCE ENGINE IS FOUND AND SSTI IS A GO
- [ ] check the environment for a list of object, variables, and methods
	- [ ] look for anything non-standard built by the site devs
- [ ] check the list of extensions and plugins
- [ ] check for debug or access to read settings
- [ ] try to find a method to call something with exec
	- [ ] calling runtime, or importing os/system can work
	- [ ] look for language specific workarounds to execute code
	- [ ] some languages require variable chaining of methods
- [ ] look for methods to read or write local files

## Capabilities

Reading Files  
Remote Code Execution  
Exposure of sensitive information  

## Found In

User Input

## Tools/Examples

simple detection
```
${7*7}
a{*comment*}b
{{7*7}}
^{7*7}
{{7*'7'}}
${'z'.join('ab')}
```
{% endraw %}

![template-decision-tree.png](/img/webapp_notes/template-decision-tree.png)

more complex detection:
[https://cheatsheet.hackmanit.de/template-injection-table/](https://cheatsheet.hackmanit.de/template-injection-table/)

payloads:
[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)

for a refresher:
[https://www.youtube.com/watch?v=SN6EVIG4c-0](https://www.youtube.com/watch?v=SN6EVIG4c-0)

![SSTI-complex-tree.png](/img/webapp_notes/SSTI-complex-tree.png)




