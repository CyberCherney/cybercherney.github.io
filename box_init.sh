#!/bin/bash

# Used for creating HTB markdown post shells and directories

read -p "Enter the challenge name: " name
read -p "Enter the box difficulty: " diff
lower=`echo "${name,,}"`
upper=`echo "${name^}"`

dir="_activeboxes/$lower"

mkdir $dir

cat << header > $dir/-HTB_$upper.md
---
layout: post
title: "HTB: $upper"
box: $lower
img: /img/$lower/$lower
author: Andrew Cherney
date: 
tags: htb $diff-box
icon: "assets/icons/$lower.png"
post_description: ""
---

# Summary

{{ page.post_description }}

# Enumeration

{% include img_link src="/img/$lower/$lower_front_page" alt="front_page" ext="png" trunc=600 %}

![]({{ page.img }}_pic.png)



header


