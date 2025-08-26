# Substitution (CS50 Pset2)

## Problem
Find problem [here](https://cs50.harvard.edu/x/psets/2/substitution/)

Implement substitution cipher encryption using a 26-character key.

## Approach
The code below uses **pointer arithmetic** instead of array indexing (unlike the Caesar cipher which uses array indexing).

## Key Features
- **Pointer Arithmetic**: Uses pointer manipulation instead of array indexing
- **Unique Key Validation**: Ensures the 26-character key contains only unique alphabetic characters
- **Case Preservation**: Maintains the original case of letters in the output

## Code Structure
- `is_unique_alpha()`: Validates that the key contains 26 unique alphabetic characters
- `get_input()`: Gets plaintext using fgets() and handles newline removal
- `substitute()`: Implements the substitution cipher using pointer arithmetic
- `main()`: Handles command-line arguments and orchestrates encryption

## Substitution Algorithm
For each character:
- If uppercase: `*c = toupper(k[*p-'A'])`
- If lowercase: `*c = tolower(k[*p-'a'])`
- If non-alphabetic: Keep unchanged
- Move both pointers: `c++` and `p++`

## Key Validation
The `is_unique_alpha()` function:
1. Uses an array `seen[26]` to track which letters have been seen
2. Checks each character is alphabetic using `isalpha()`
3. Converts to uppercase and checks for duplicates using `seen[c-'A']++`
4. Returns 0 if any character is non-alphabetic or duplicate

## Pointer Arithmetic vs Array Indexing
- **Caesar cipher**: Uses array indexing `c[i] = 'A' + (p[i] - 'A' + k) % 26`
- **Substitution cipher**: Uses pointer arithmetic `*c = toupper(k[*p-'A'])`

## Usage
```bash
./substitution YTNSHKVEFXRBAUQZCLWDMIPGJO
plaintext: HELLO
ciphertext: EHBBQ
```

## Key Concepts
- **Pointer Arithmetic**: Manipulating pointers directly instead of using array indices
- **Key Validation**: Ensuring the substitution key is valid (26 unique alphabetic characters)
- **Case Handling**: Preserving the original case of letters in the ciphertext
- **Command-line Arguments**: Using argc and argv for program input
- **String Manipulation**: Handling newlines and null termination

## Code
See [`substitution.c`](substitution.c) for full implementation.
