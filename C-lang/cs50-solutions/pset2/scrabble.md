# Scrabble (CS50 Pset2)

## Problem
Find problem [here](https://cs50.harvard.edu/x/psets/2/scrabble/)

Calculate word scores based on letter values and determine the winner.

## Approach
Implement Scrabble scoring system where each letter has a point value, and compare two words to determine the winner.

## Letter Values
- 1 point: A, E, I, L, N, O, R, S, T, U
- 2 points: D, G
- 3 points: B, C, M, P
- 4 points: F, H, V, W, Y
- 5 points: K
- 8 points: J, X
- 10 points: Q, Z

## Code Structure
- `get_input()`: Gets words from two players
- `to_uppercase()`: Converts words to uppercase for consistent scoring
- `scores()`: Calculates score for a given word
- `print_result()`: Compares scores and announces winner
- `main()`: Orchestrates the game flow

## Algorithm
1. Get two words from players
2. Convert both words to uppercase
3. Calculate score for each word by looking up letter values
4. Compare scores and determine winner

## Alternative Approach
A much simpler and more efficient approach using an array lookup:

```c
int scores_table[26] = {1, 3, 3, 2, 1, 4, 2, 4, 1, 8, 5, 1, 3, 1, 1, 3, 10, 1, 1, 1, 1, 4, 4, 8, 4, 10};

int scores(char *word) {
    int score=0;
    for (int i=0; word[i]; i++) {
        char c = toupper(word[i]);
        if (c >= 'A' && c <= 'Z') {
            score+= scores_table[c-'A'];
        }
    }
    return score;
}
```

This approach:
- Removes the need for separate `to_uppercase()` function
- Eliminates nested loops and `goto` statements
- Uses single array lookup for much faster performance

## Key Concepts
- **String Manipulation**: Converting case and iterating through characters
- **Array Usage**: Storing letter values and word data
- **Function Design**: Modular approach with separate functions for different tasks
- **Input Validation**: Ensuring words are not empty

## Code
See [`scrabble.c`](scrabble.c) for full implementation.
