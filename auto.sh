#!/bin/bash
# automates the creation of and uploading of posts
# in addition to prepping images to markdown format


# creates directory and post shell
function box_init () {

read -p "Enter the challenge name: " name
read -p "Enter the box difficulty: " diff
lower=`echo "${name,,}"`
upper=`echo "${name^}"`
lower_front_page=$lower"_front_page"

dir="_activeboxes/$lower"

# check to not overwrite
if [ -d $dir ]; then
    echo 'Directory already exists'
    exit 1
fi

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
}


# takes pngs within a directory and echoes them into a markdown format
# useful for when I have 20 images to put in a post
function prep_image () {

read -p "Enter the box: " box_raw
box=`echo "${box_raw,,}"`
directory="_activeboxes/$box"

# directory check
if [ ! -d $directory ]; then
    echo "No directory named $box"
    exit 1
fi

length=$((${#box}+1))
imgs=$(ls $directory | grep "$(echo $box)_")

for element in $imgs; do
    file=$(echo "$element" | cut -b "$length"-)
    echo "![]({{ page.img }}$file)"
done
}


# script that adds date to post name and tags
# then moves images and post to proper directories prior to push
function upload_post () {

# prepping variables for post name and directory
read -p "Enter the post to upload: " post_name
post=`echo ${post_name,,}`
directory=`echo "_activeboxes/$post"`

# directory check
if [ ! -d $directory ]; then
    echo "No directory named $box"
    exit 1
fi

# modifying and moving post
file=`ls _activeboxes/$post | grep '.md$'`
date=`date  +"%Y-%m-%d"`
name=`echo "$date$file"`
sed -i "/date:/s/$/$date/" $directory/$file
mv $directory/$file _posts/$name

# moving icon
icon=`echo "$post.png"`
mv $directory/$icon assets/icons

# moving other images
mv $directory img
}



while [[ $# -gt 0 ]]; do 
    case $1 in
        -h|--help)
            echo "-i or --init to initialize box directory/post"
            echo "-p or --prep to format images within box directory to markdown"
            echo "-u or --upload to prep post and images for upload"
            shift
            ;;
        -i|--init)
            echo "Running box init script"
            box_init
            shift
            ;;
        -p|--prep)
            echo "Running image prepping script"
            prep_image
            shift
            ;;
        -u|--upload)
            echo "Running post upload script"
            upload_post
            shift
            ;;
        *)
            shift
            ;;
    esac
done

