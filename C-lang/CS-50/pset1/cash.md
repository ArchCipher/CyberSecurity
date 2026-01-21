# Cash: USA (CS50 Pset1)

## Problem
Find problem [here](https://cs50.harvard.edu/x/psets/1/cash/)

Implement a greedy algorithm that minimizes the number of coins returned as change.

## Approach
Greedy algorithms: that minimize numbers of coins returned as change.

Available coins: quarters (25¢), dimes (10¢), nickels (5¢), and pennies (1¢)

## Algorithm
The greedy approach always takes the largest coin possible:
1. Use quarters (25¢) until remaining amount < 25
2. Use dimes (10¢) until remaining amount < 10
3. Use nickels (5¢) until remaining amount < 5
4. Use pennies (1¢) for the remainder

## Code Structure
- `get_input()`: Gets and validates user input (1-99 cents)
- `change()`: Implements the greedy algorithm using pointers to track coin counts
- `main()`: Orchestrates the program and displays results

## Example Output
```
Change owed: 99
Total coins: 9
Quarters: 3
Dimes: 2
Nickels: 0
Pennies: 4
```

## Key Concepts
- **Greedy Algorithm**: Always choose the largest possible coin at each step
- **Pointers**: Used to modify coin count variables from within the function
- **Input Validation**: Ensures input is positive and within reasonable bounds

## Code
See [`cash.c`](cash.c) for full implementation.
