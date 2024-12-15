---
layout: adventofcyber2024
title: "Day 5: Print Queue"
author: "Andrew Cherney"
date: 2024-12-15 17:45:37
tags: 
- python
- regex
---


# {{ page.title }}

The detailed rundown can be found here: [https://adventofcode.com/2024/day/5](https://adventofcode.com/2024/day/5).


### Part One

TLDR; I will be given a two part file input, first part is a pair of pages `A|B` where page A has to be in the list before page B. I need to find lists that are in the correct order already and add the middle values. The data will look something like this: 

```
47|53
97|13
97|61
97|47
75|29
61|13
75|53
29|13
97|29
53|29
61|53
97|53
61|29
47|13
75|47
97|75
47|61
75|61
47|29
75|13
53|13

75,47,61,53,29
97,61,53,29,13
75,29,13
75,97,47,61,53
61,13,29
97,13,75,29,47
```

The simple approach I took was to break down the input data with regex into two lists containing rules to follow, and print orders, then cycle through the print orders and determine "relevant" rules which only contain the numbers inside of the print order list. Once I have that it's simple to add a check to see if they pass and then sum them together.


```python
def part_one():
    #order_and_rules = import_dataset("day5.txt")
    order_and_rules = import_dataset("day5_real.txt")
    rules = []
    print_orders = []
    total_correct = 0
    for line in order_and_rules:
        if re.search(r"[0-9]+\|[0-9]+", line):
            rules.append(line.strip().split("|"))
        elif re.search(r"([0-9]+,)+[0-9]+", line):
            print_orders.append(line.strip())

    for page_order in print_orders:
        pages = page_order.split(",")
        relevant_rules = []
        for page in pages:
            for rule in rules:
                if page == rule[0]:
                    relevant_rules.append(rule)
        i=0
        while i < len(relevant_rules):
            if relevant_rules[i][1] not in pages:
                relevant_rules.pop(i)
            else:
                i += 1

        correct_order = True
        for case in relevant_rules:
            start = case[0]
            check = case[1]
            if pages.index(start) > pages.index(check):
                correct_order = False
                break

        if correct_order == True:
            middle = int((len(pages)-1)/2)
            total_correct += int(pages[middle])

    print("Total sum of correct prints: %s" % total_correct)
```

Example data gave 143, the correct result. The real data gave the correct result on the first try. I could have refined down some of the functionality inside of part_one() to make it look nicer and more reusable but I opted to keep the ugly nested loops.

### Part Two

Next knowing which ones are in the correct order isn't all we need to determine, we need to place them into the correct order. My initial idea that I had was to create a recursive check/correction that will swap the two values that are incorrect. There were a few bugs that I overlooked as something more than they were during testing. Notably I ran a loop for the length of the print queue instead of the loop resetting on a correction to check for additional errors. The sample data was short enough to ignore this flaw.

```python
def part_two():
    #order_and_rules = import_dataset("debug.txt")
    #order_and_rules = import_dataset("day5.txt")
    order_and_rules = import_dataset("day5_real.txt")
    rules = []
    print_orders = []
    total_corrected = 0
    for line in order_and_rules:
        if re.search(r"[0-9]+\|[0-9]+", line):
            rules.append(line.strip().split("|"))
        elif re.search(r"([0-9]+,)+[0-9]+", line):
            print_orders.append(line.strip())

    for page_order in print_orders:
        pages = page_order.split(",")
        relevant_rules = []
        for page in pages:
            for rule in rules:
                if page == rule[0]:
                    relevant_rules.append(rule)
        i=0
        while i < len(relevant_rules):
            if relevant_rules[i][1] not in pages:
                relevant_rules.pop(i)
            else:
                i += 1

        corrected = False
        i=0
        while i < len(relevant_rules):
            start = relevant_rules[i][0]
            check = relevant_rules[i][1]
            if pages.index(start) > pages.index(check):
                #print(pages)
                corrected = True
                pages.pop(pages.index(check))
                pages.insert(pages.index(start)+1, check)
                #pages[pages.index(start)] = check
                #pages[pages.index(check)] = start
                i = 0
            else:
                i+=1 

        if corrected == True:
            total_corrected += int(pages[int(len(pages)/2)])

    print("Total sum of corrected prints: %s" % total_corrected)
```

You'll even see a debug file where I corrected a list of print queues then re-ran them to check if there would be 0 corrected. It was the pivotal moment to fix my code when I realized many queues weren't processed properly. Both the transposing method and the insert-pop method work for placing the correct values. I tried both, one before my issues and that wasn't the problem. 

Example with this finalized code gave me 123, and after about 7 tries I got the proper number with the refined and properly functioning code above. 

