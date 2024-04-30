#!/bin/bash
# Takes pngs within a directory and places them into a markdown format
# Useful for when I have 20 images to put in a post

read -p "Enter the box: " box
directory="_activeboxes/$box"
length=$((${#box}+1))
imgs=$(ls $directory | grep "$(echo $box)_")

for element in $imgs; do
    file=$(echo "$element" | cut -b "$length"-)
    echo "![]({{ page.img }}$file)"
done

