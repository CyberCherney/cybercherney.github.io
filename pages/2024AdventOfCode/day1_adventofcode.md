---
layout: adventofcyber2024
title: "Day 1: Historian Hysteria"
author: "Andrew Cherney"
date: 2024-12-10 23:52:09
tags: 
- python
---

# {{ page.title }}

The detailed rundown can be found here: [https://adventofcode.com/2024/day/1](https://adventofcode.com/2024/day/1).

### Part One

The goal is to take a list of two numbers separated by spaces and sort them, then compare the difference between each element and find the sum. An example data set is below:

```
3   4
4   3
2   5
1   3
3   9
3   3
```

To achieve this a simple split can be used, then assigning the resulting array into two different arrays used for the comparison. **array.sort()** can be used to sort them in ascending order, and a simple loop can be used to compare each element and find the difference.

```python
#!/bin/python3.9

def import_dataset(filename):
    data = open(filename, "r")
    return data

def main():
    first_array = []
    second_array = []
    data = import_dataset("day1.txt")
    for line in data:
        nums = line.split()
        first_array.append(int(nums[0]))
        second_array.append(int(nums[1]))

    first_array.sort()
    second_array.sort()

    total_distance = 0
    for i in range(0,len(first_array)):
        diff = abs(first_array[i] - second_array[i])
        total_distance += diff

    print("Total distance: %s" % total_distance)


if __name__ == "__main__":
    main()
```

The example data yielded an 11 as a result from the code, and I answered the puzzle correctly on the first try with the above code.

### Part Two

Next challenge is to find the total similarity. That number is specifically found by taking the number of found occurrences of element from array one in array two, then multiplying it by the element itself, luckily for us always a number. So in the example above 3 occurs 3 times in array two, so the similarity would increment by 9.

To search for something in an array **count()** can be used. Append the following to the bottom of **main** and it will also calculate the similarity.

```python
    total_similarity = 0
    for i in first_array:
        sim = second_array.count(i)
        if sim > 0:
            total_similarity += (i * sim)
    
    print("Total similarity: %s" % total_similarity)
```

The example data got 31 and again I answered the puzzle correctly on the first try. 
