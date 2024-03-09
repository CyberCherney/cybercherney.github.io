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
author: Andrew Cherney
date: 
tags: htb $diff-box
icon: "assets/icons/$lower.png"
post_description: ""
---

# Summary

{{ page.post_description }}

# Enumeration


header


