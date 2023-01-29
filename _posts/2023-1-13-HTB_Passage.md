---
layout: post
title: "HTB: Passage"
author: Andrew Cherney
date: 2023-01-13 19:49:23
icon: ""
tags: htb medium-box
post_description: "The solution to Passage is quite research heavy and not so technically demanding. The CMS is vulnerable due to its specific version which gives a foothold, a pivot takes place to gain better permissions, and root can be obtained from a usbcreator d-bus service which allows for copying files as root."
---

<h1>Summary</h1>

The solution to Passage is quite research heavy and not so technically demanding. The CMS is vulnerable due to its specific version which gives a foothold, a pivot takes place to gain better permissions, and root can be obtained from a usbcreator d-bus service which allows for copying files as root.

<h1>Enumeration</h1>

<h2>rustscan</h2>

```bash
rustscan 10.10.10.206 | tee results.scan
```

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 62 OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVnCUEEK8NK4naCBGc9im6v6c67d5w/z/i72QIXW9JPJ6bv/rdc45FOdiOSovmWW6onhKbdUje+8NKX1LvHIiotFhc66Jih+AW8aeK6pIsywDxtoUwBcKcaPkVFIiFUZ3UWOsWMi+qYTFGg2DEi3OHHWSMSPzVTh+YIsCzkRCHwcecTBNipHK645LwdaBLESJBUieIwuIh8icoESGaNcirD/DkJjjQ3xKSc4nbMnD7D6C1tIgF9TGZadvQNqMgSmJJRFk/hVeA/PReo4Z+WrWTvPuFiTFr8RW+yY/nHWrG6LfldCUwpz0jj/kDFGUDYHLBEN7nsFZx4boP8+p52D8F
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCdB2wKcMmurynbHuHifOk3OGwNcZ1/7kTJM67u+Cm/6np9tRhyFrjnhcsmydEtLwGiiY5+tUjr2qeTLsrgvzsY=
|   256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGRIhMr/zUartoStYphvYD6kVzr7TDo+gIQfS2WwhSBd
80/tcp open  http    syn-ack ttl 62 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Passage News
```

<h2>Port 80 - Apache</h2>

![Passage News]()


