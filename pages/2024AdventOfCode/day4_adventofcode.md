---
layout: adventofcyber2024
title: "Day 4: Ceres Search"
author: "Andrew Cherney"
date: 2024-12-12 00:58:58
tags: 
- python
---

# {{ page.title }}

The detailed rundown can be found here: [https://adventofcode.com/2024/day/4](https://adventofcode.com/2024/day/4).

### Part One

The TLDR of the requirements for day 4 is to create a crude crossword "solver" where the goal is to find all occurrences of a specific word. This is straightforward, as it means I can import the data and use list() + strip() to turn the data given into a grid that I can reference easily. It allows me to find any character under the scheme `crossword[row][column]`.

Next comes the part of finding if the word fits after finding a valid starting point. I opted to add logic that would check if a position was valid, ie greater than or equal to 0, and less than or equal to the length of the row/column. If that turned a valid result I can assemble the potential word in a given direction and compare it to the string we are looking for, and increment on success. Admittedly there is a smarter way to handle all the different directions but I opted for an if statement per as it was simpler to manage and troubleshoot. 

```python
def import_dataset(filename):
    data = open(filename, "r")
    return data

def assemble_array(data):
    out_array = []
    for line in data:
        tmp = list(line.strip())
        out_array.append(tmp)
    return out_array

def is_position_valid(row,column,rows,columns):
    if row >= 0 and column >= 0 and row < rows and column < columns:
        return True
    else:
        return False

def part_one():
    data = import_dataset("day4.txt")
    crossword = assemble_array(data)
    search_string = "XMAS"
    len_from_first = len(search_string)-1
    occurrence = 0
    total_occurrence = 0

    height = len(crossword)
    length = len(crossword[0])

    for i in range(0,len(crossword)):
        row = crossword[i]
        for j in range(0,len(row)):
            if row[j] == search_string[0]:
                if is_position_valid(i-len_from_first,j-len_from_first,height,length) == True: # UL
                    check_string = "" + row[j]
                    for x in range(1,len(search_string)):
                        letter = crossword[i-x][j-x]
                        check_string += letter
                        
                    if check_string == search_string:
                        occurrence += 1

                if is_position_valid(i-len_from_first,j,height,length) == True: # U
                    check_string = "" + row[j]
                    for x in range(1,len(search_string)):
                        letter = crossword[i-x][j]
                        check_string += letter
                        
                    if check_string == search_string:
                        occurrence += 1

                if is_position_valid(i-len_from_first,j+len_from_first,height,length) == True: # UR
                    check_string = "" + row[j]
                    for x in range(1,len(search_string)):
                        letter = crossword[i-x][j+x]
                        check_string += letter

                    if check_string == search_string:
                        occurrence += 1

                if is_position_valid(i,j-len_from_first,height,length) == True: # L
                    check_string = "" + row[j]
                    for x in range(1,len(search_string)):
                        letter = crossword[i][j-x]
                        check_string += letter

                    if check_string == search_string:
                        occurrence += 1

                if is_position_valid(i,j+len_from_first,height,length) == True: # R
                    check_string = "" + row[j]
                    for x in range(1,len(search_string)):
                        letter = crossword[i][j+x]
                        check_string += letter

                    if check_string == search_string:
                        occurrence += 1

                if is_position_valid(i+len_from_first,j-len_from_first,height,length) == True: # DL
                    check_string = "" + row[j]
                    for x in range(1,len(search_string)):
                        letter = crossword[i+x][j-x]
                        check_string += letter

                    if check_string == search_string:
                        occurrence += 1

                if is_position_valid(i+len_from_first,j,height,length) == True: # D
                    check_string = "" + row[j]
                    for x in range(1,len(search_string)):
                        letter = crossword[i+x][j]
                        check_string += letter

                    if check_string == search_string:
                        occurrence += 1

                if is_position_valid(i+len_from_first,j+len_from_first,height,length) == True: # DR
                    check_string = "" + row[j]
                    for x in range(1,len(search_string)):
                        letter = crossword[i+x][j+x]
                        check_string += letter

                    if check_string == search_string:
                        occurrence += 1

                if occurrence > 0:
                    total_occurrence += occurrence
                    occurrence = 0

    print("Total occurrence of %s: %s" % (search_string,total_occurrence))

def main():
    part_one()

if __name__ == "__main__":
    main()


```

It's notable here I made the valid position functionality a function as I suspected I would need to reuse it for part 2 and multiple times in part 1. Additionally the array assembler was defined here as I have a hunch the copy paste power of using this for future days will save me at least some time. 

The example properly gave a8 and the real data gave the correct answer first runthrough.


### Part Two

Next to my amazement it was an easier task. The goal was not to find "XMAS" it was to find MAS in an X shape:

```
M.S
.A.
M.S
```

With what I wrote before this is trivial in fact and I can reuse the old code and functions to solve this quickly. Notable here that I check only two of the corners to save some time in the processing (though it's literally negligible). Then I assemble what the diagonal strings are, and check if they are "MAS" or "SAM", if they both are one of those I increment.

```python
def part_two():
    data = import_dataset("day4.txt")
    crossword = assemble_array(data)
    occurrence = 0
    xmas_occurrence = 0

    height = len(crossword)
    length = len(crossword[0])

    for i in range(0,len(crossword)):
        row = crossword[i]
        for j in range(0,len(row)):
            if row[j] == "A":
                if is_position_valid(i-1,j-1,height,length) == True and is_position_valid(i+1,j+1,height,length) == True: 
                    ul_dr_check_string = crossword[i-1][j-1] + "A" + crossword[i+1][j+1]
                    dl_ur_check_string = crossword[i+1][j-1] + "A" + crossword[i-1][j+1]


                    if ul_dr_check_string in ("MAS","SAM") and dl_ur_check_string in ("MAS","SAM"):
                        occurrence += 1


                if occurrence > 0:
                    xmas_occurrence += occurrence
                    occurrence = 0

    print("Total X-MAS occurrences: %s" % (xmas_occurrence))
```

The example data gave 9 as expected and I got the right answer on the read data first try.
