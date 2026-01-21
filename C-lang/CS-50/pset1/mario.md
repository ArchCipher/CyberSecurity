# Mario (CS50 Pset1)

## Problem
Recreate the classic Mario pyramid using hashes, input height between 1 and 8.

## Approach
Used a nested loop: one for rows, inner loop for spaces and hashes. Validated input using a do-while loop to ensure the input is between 1 and 8.

## Example Output
```
   #  #
  ##  ##
 ###  ###
####  ####
```

## Code Structure
- `get_input()`: Validates user input to ensure it's between 1 and 8
- `mario(int n)`: Creates the pyramid pattern with the given height
- `main()`: Orchestrates the program flow

## Algorithm
1. Get valid input (1-8)
2. For each row (0 to n-1):
   - Print spaces: n-(i+1) spaces
   - Print left hashes: i+1 hashes
   - Print two spaces
   - Print right hashes: i+1 hashes
   - Print newline

## Constraints
- Input must be between 1 and 8 inclusive
- Each row has exactly two spaces between the left and right pyramids

## Code
See [`mario.c`](mario.c) for full implementation.
