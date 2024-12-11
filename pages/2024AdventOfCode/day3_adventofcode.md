---
layout: adventofcyber2024
title: "Day 3: Mull It Over"
author: "Andrew Cherney"
date: 2024-12-10 23:52:06
tags: 
- python
- regex
---

# {{ page.title }}

The detailed rundown can be found here: [https://adventofcode.com/2024/day/3](https://adventofcode.com/2024/day/3).

### Part One

We are to be given corrupted memory and need to find the **mul(#,#)** instructions and calculate them. An example of what we can be given is below:

```
xmul(2,4)%&mul[3,7]!@^do_not_mul(5,5)+mul(32,64]then(mul(11,8)mul(8,5))
```

This problem can easily be solved by using regular expressions. Searching through the memory for instances that follow the expected format then calculating those instances and finding the total sum of products. 

```python
#!/bin/python3.9
import re

def import_dataset(filename):
    data = open(filename, "r")
    return data

def part_one():
    data = import_dataset("day3.txt")
    total_product = 0
    for line in data:
        mul_array = re.findall("mul\([0-9]+,[0-9]+\)", line)

        for i in range(0,len(mul_array)):
            mul_expression = mul_array[i]
            num1 = int(mul_expression.split(",")[0][4:])
            num2 = int(mul_expression.split(",")[1][:-1])
            total_product += num1 * num2

    print("Total product: %s" % total_product)

def main():
    part_one()

if __name__ == "__main__":
    main()
```

Breaking this down after reading the data from a file I use re to findall occurrences of the regular expression `mul\([0-9]+,[0-9]+\)`, this searches for the string **mul**, the character **(** (needing to be escaped with `\`) then the brackets define possible characters that can exist, here is any number, followed by **+** which means it can occur any number of times until it gets to a non-numeric character. **,** is then followed by another integer of any size, and finally a closing **)**, all of that to say it looks for the format **mul(#,#)**.

Post finding all instructions I use split to split at **,** and remove the first 4 characters, and the last 1 during assignment, and multiply the result together. The sample answer was 161 which was obtained with this code, and running it on the real data of [https://adventofcode.com/2024/day/3/input](https://adventofcode.com/2024/day/3/input) gave me another gold star.

### Part Two

It turns out some of the memory is in fact readable and usable. There are **do()** and **don't()** that can be found which modify what **mul** should be calculated. Any **mul** after a **don't()** is to be ignored. If I can get a list of instructions it would be trivial to set a switch that I can change to True or False depending if **do/don't** was read last. The problem here was to get a list of instructions in a format that I could read. 

The answer to this problem was in fact more regex. If I added a couple **|** to the regular expression it would allow me to both search for multiple instructions and as a byproduct format the resulting array in a way that I can process. Below is an example of data to use.

```
xmul(2,4)&mul[3,7]!^don't()_mul(5,5)+mul(32,64](mul(11,8)undo()?mul(8,5))
```

The findall returned a genuinely ugly looking tuple with only the found element filled out. `('', 'mul(2,4)', '')` was the result, and to remedy this I created a string that was a concatenation of all the tuple values and appended it to the instructions array.

```python
def part_two():
    data = import_dataset("day3.txt")
    total_enabled_product = 0
    instructions = []
    for line in data:
        mul_array = re.findall(r"(do\(\))|(mul\([0-9]+,[0-9]+\))|(don't\(\))", line)
        for i in range(0,len(mul_array)):
            tmp = mul_array[i]
            command = tmp[0]+tmp[1]+tmp[2]
            instructions.append(command)
    #print(instructions)

    execute = True
    for i in instructions:
        if i == "do()":
            execute = True
        elif i == "don't()":
            execute = False
            
        test = re.findall(r"(mul\([0-9]+,[0-9]+\))", i)
        if test != [] and execute == True:
            mul_expression = i
            num1 = int(mul_expression.split(",")[0][4:])
            num2 = int(mul_expression.split(",")[1][:-1])
            total_enabled_product += num1 * num2

    print("Total enabled product: %s" % total_enabled_product)
```

The last piece of the puzzle was to add the instruction reader that processed the array I constructed. To do this I simply created a switch called **execute** to determine if the **mul** instructions should be ignored or processed, then with more regex I checked for **mul** and ran through the instructions array. 

The example data result is meant to be 48, which it was. And the actual data result was 8 digits long and I answered it first try no troubleshooting. 
