# Custom strlen Function

## Problem
Create a custom implementation of the `strlen` function using pointer arithmetic instead of array indexing.

## Approach
Implement a function that counts characters in a string by incrementing a pointer until it reaches the null terminator, demonstrating pointer manipulation and string processing.

## Code Structure
- `ft_strlen()`: Custom string length function using pointer arithmetic
- `ft_strlen.h`: Header file with function declaration and header guards
- `test_strlen.c`: Test file demonstrating usage

## Algorithm
1. Initialize counter to 0
2. While current character is not null terminator:
   - Increment counter
   - Move pointer to next character
3. Return final count

## Key Concepts
- **Pointer Arithmetic**: Using `s++` to traverse the string
- **String Termination**: Checking for `'\0'` null terminator
- **Header Files**: Function declarations and header guards
- **Modular Design**: Separating implementation from testing

### Header Guards
A header file (`.h`) typically contains function declarations, type definitions, and optionally macros. 

A macro is a rule handled by the C preprocessor — it tells the compiler to substitute code or text before actual compilation. Macros are defined using `#define`. One common use of macros is in header guards, which prevent the same header file from being included multiple times.

`#ifndef FT_STRLEN_H` (if not defined) checks if a macro (`FT_STRLEN_H`) is not yet defined. If not, `#define FT_STRLEN_H` defines it and includes the following code. `#endif` closes the conditional. The guard prevents multiple inclusions of the same declarations, which could cause compilation errors.

### Macro Naming Rules
- Preprocessor macros must follow C identifier rules:
    - Letters (A–Z, a–z), digits (0–9), underscores (_)
    - But cannot start with a digit, cannot contain dots (.)
- The preprocessor treats `.` as a punctuation symbol, not a valid part of a macro name.

## Compilation & Testing

To compile and test the function:
```bash
clang -g ft_strlen.c test_strlen.c -o test_strlen
./test_strlen
```

## Code
See [`ft_strlen.c`](ft_strlen.c) for full implementation.
