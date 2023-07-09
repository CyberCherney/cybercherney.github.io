---
layout: kringlecon2022
title: "Tolkien Ring"
author: "Andrew Cherney"
date: 2023-01-15 19:52:13
tags: kringlecon windows wireshark suricata
---
## Suricata Regatta
***
___
investigate the suspicious.pcap
add created rules to suricata.rules
run `./rule checker` to see check solution

***
#### Question

1. Create Suricata rule to catch DNS lookups for adv.epostoday.uk, any match make the alert message read "Known bad DNS lookup, possible Dridex infection"

#### Answer

`alert dns $HOME_NET any -> any any (msg:"Known bad DNS lookup, possible Dridex infection"; dns.query; content:"adv.epostoday.uk"; nocase; rev:1;)`

___

#### Question

2. STINC thanks you for your work with that DNS record! In this PCAP, it points to 192.185.57.242.
Develop a Suricata rule that alerts whenever the infected IP address 192.185.57.242 communicates with internal systems over HTTP.
When there's a match, the message (msg) should read Investigate suspicious connections, possible Dridex infection

#### Answer

`alert http any any <> [192.185.57.242] any (msg:"Investigate suspicious connections, possible Dridex infection"; sid:1;)`

___
#### Question

3. We heard that some naughty actors are using TLS certificates with a specific CN.
Develop a Suricata rule to match and alert on an SSL certificate for heardbellith.Icanwepeh.nagoya.
When your rule matches, the message (msg) should read Investigate bad certificates, possible Dridex infection

#### Answer

`alert tls any any -> any any (msg:"Investigate bad certificates, possible Dridex infection"; tls.cert_issuer; content:"heardbellith.Icanwepeh.nagoya"; nocase; sid:2;)`

___
#### Question

4. OK, one more to rule them all and in the darkness find them.
Let's watch for one line from the JavaScript: let byteCharacters = atob
Oh, and that string might be GZip compressed - I hope that's OK!
Just in case they try this again, please alert on that HTTP data with message Suspicious JavaScript function, possible Dridex infection

#### Answer

Tried to use `http.content_type; content:"text/javascript";` and `http.accept_enc; content:"gzip";` but neither are needed for some reason.

`alert http any any -> any any (msg:"Suspicious JavaScript function, possible Dridex infection"; file.data; content:"let byteCharacters = atob"; sid:4;)`

___





## Windows Event Logs 
___
___
#### Question

1. What month/day/year did the attack take place?

#### Answer

Look through the logs for activity that is not normal, could filter by informational and skim through powershell commands looking for the day where unusual commands are used. Best way to do this, open the .evtx file in event viewer and save as a .txt, then import into a linux vm and use grep to find what you're looking for. 

Search for some key words like secret, password, admin, ForEach, etc.. and use -n to specify line number and manually investigate.

`cat winevent.txt | grep -n "secret"`

Answer: 12/24/2022

___
#### Question

2. An attacker got a secret from a file, What was the original file's name?

#### Answer

Same method as last question only specify secret and check line number

Answer: Recipe

___
#### Question

3. The contents of the previous file were retrieved, changed, and stored to a variable by the attacker. This was done multiple times. Submit the last full Powershell line that performed only these actions.

#### Answer

`cat winevent.txt | grep -n "\\$"`

Answer: `$foo = Get-Content .\Recipe| % {$_ -replace 'honey', 'fish oil'} $foo | Add-Content -Path 'recipe_updated.txt'`

___
#### Question

4. After storing the altered file contents into the variable, the attacker used the variable to run a separate command that wrote the modified data to a file. This was done multiple times. Submit the last full Powershell line that performed only this action.

#### Answer

search for the last time `foo` is used

`cat winevent.txt | grep -n "foo"`

Answer: `$foo | Add-Content -Path 'Recipe'`

___
#### Question

5. The attacker ran the previous command against one file multiple times. What is the name of this file?

#### Answer

Use output from previous command

Answer: Recipe.txt

___
#### Question

6. Were any files deleted?

#### Answer

`cat winevent.txt | grep -n "del"`

Answer: Yes

___
#### Question

7. Was the original file (from question 2) deleted?

#### Answer

Unsure why

Answer: No

___
#### Question

8. What is the Event ID of the logs that show the acutal command lines the attacker typed and ran?

#### Answer

Check the Event ID for Executing a Remote Command

Answer: 4104

___
#### Question

9. Is the secret ingredient compromied?

#### Answer

Answer: Yes

___
#### Question

10. What is the secret ingredient?

#### Answer

Answer: honey

___




## Wireshark Phishing
___
___
#### Question

1. There are objects in the PCAP file that can be exported by Wireshark and/or Tshark. What type of objects can be exported from this PCAP?

#### Answer

this pcap captured regular web traffic of a file download, so necessarily it would be http

Answer: http

___
#### Question

2. What is the file name of the largest file we can export?

#### Answer

filter by http and look for any GET requests on files, alternatively go to File-->Export Objects-->HTTP and view the sizes of the files

Answer: app.php

___
#### Question

3. What packet number starts that app.php file?

#### Answer

In http object list view the starting packet

Answer: 687

___
#### Question

4. What is the IP of the Apache Server

#### Answer

Look at destination in any GET request

Answer: 192.185.57.242

___
#### Question

5. What file is saved to the infected host?

#### Answer

Look at the php code and find the part where is mentions `saveAs(blob1, 'Ref_Sept24-2020.zip'):\n`

Answer: Ref_Sept24-2020.zip

___
#### Question

6. Attackers used bad TLS certificates in this traffic. Which countries were they registered to?

#### Answer

Search for ssl.handshake.type == 2, in info look for Handshake Protocol: Certificate --> Certificates --> Certificate --> signedCertificate --> issuer --> countryName look at countryName and decipher.

Country Codes: US, IE, IL, SS

Answer: Ireland, Israel, South Sudan, United States

___
#### Question

7. Is the host infected (Yes/No)?

#### Answer

Answer: Yes

___









