# Caesar (CS50 Pset2)

## Problem
Find problem [here](https://cs50.harvard.edu/x/psets/2/caesar/)

Implement Caesar cipher encryption using command-line arguments.

## Approach
Using fgets() instead of scanf() for better input handling. The Caesar cipher shifts each letter by a fixed number of positions in the alphabet.

## Key Features
- **fgets() vs scanf()**: fgets() reads up to 999 characters and includes the newline \n at the end if there's room
- **Newline Handling**: If the text is `Hello world!<Enter>`, it becomes "Hello world!\n\0". The code removes the \n to avoid double newlines
- **Command-line Arguments**: Takes the key as a command-line argument

## Code Structure
- `is_digit()`: Validates that the command-line argument is a digit
- `get_input()`: Gets plaintext using fgets() and handles newline removal
- `rotate()`: Implements the Caesar cipher algorithm
- `main()`: Handles command-line arguments and orchestrates encryption

## Caesar Cipher Algorithm
For each character:
- If uppercase: `c[i] = 'A' + (p[i] - 'A' + k) % 26`
- If lowercase: `c[i] = 'a' + (p[i] - 'a' + k) % 26`
- If non-alphabetic: Keep unchanged

## Why the Formula Works
Instead of `c[i] = (p[i] + k) % 26`:
- If p[i] = 'A' (65) and k = 2: 65 + 2 = 67 → 67 % 26 = 15 → ASCII 15 is a control character
- Using `'A' + (p[i] - 'A' + k) % 26`:
  - 'A' + ('A' - 'A' + 2) % 26 = 'A' + (0 + 2) % 26 = 'A' + 2 = 'C'

This uses **array indexing** approach. The substitution cipher uses **pointer arithmetic** instead.

## Usage
```bash
./caesar 13
plaintext: Hello, World!
ciphertext: uryyb, jbeyq!
```

## Key Concepts
- **Command-line Arguments**: Using argc and argv for program input
- **String Manipulation**: Handling newlines and null termination
- **Modular Arithmetic**: Ensuring letters wrap around the alphabet
- **Input Validation**: Checking for valid numeric key
- **Character Classification**: Using isupper() and islower()

## Code
See [`caesar.c`](caesar.c) for full implementation.
