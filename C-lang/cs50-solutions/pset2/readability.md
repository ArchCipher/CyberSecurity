# Readability (CS50 Pset2)

## Problem
Find problem [here](https://cs50.harvard.edu/x/psets/2/readability/)

Calculate the reading level of text using the Coleman-Liau index.

## Approach
A number of "readability tests" have been developed over the years that define formulas for computing the reading level of a text. One such readability test is the Coleman-Liau index. The Coleman-Liau index of a text is designed to output that (U.S.) grade level that is needed to understand some text.

## Formula
`index = 0.0588 * L - 0.296 * S - 15.8`

where:
- L is the average number of letters per 100 words in the text
- S is the average number of sentences per 100 words in the text

## Code Structure
- `get_text()`: Gets text input from user
- `parse_text()`: Analyzes text to count letters, words, and sentences
- `calculate_index()`: Applies Coleman-Liau formula and determines grade level
- `main()`: Orchestrates the program flow

## Algorithm
1. Get text input from user
2. Parse text to count:
   - Letters (alphabetic characters only)
   - Words (sequences separated by whitespace)
   - Sentences (ending with ., !, or ?)
3. Calculate L and S values (per 100 words)
4. Apply Coleman-Liau formula
5. Round to nearest grade and display result

## Text Parsing Logic
- **Letters**: Count only alphabetic characters using `isalpha()`
- **Words**: Count sequences of non-whitespace characters using a flag to track word boundaries
- **Sentences**: Count occurrences of ., !, or ? punctuation marks

## Grade Levels
- Below 1: "Before Grade 1"
- 1-15: "Grade X"
- 16+: "Grade 16+"

## Key Concepts
- **Text Analysis**: Parsing and counting different text elements
- **Mathematical Formulas**: Implementing the Coleman-Liau index
- **Floating Point Arithmetic**: Handling decimal calculations
- **Input Validation**: Checking for empty text
- **Character Classification**: Using `ctype.h` functions

## Code
See [`readability.c`](readability.c) for full implementation.
