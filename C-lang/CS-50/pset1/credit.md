# Credit Card Checksum (CS50 Pset1)

## Problem
Find problem [here](https://cs50.harvard.edu/x/psets/1/credit/)

Validate credit card numbers using Luhn's Algorithm.

## Approach
Luhn's Algorithm implementation to validate credit card numbers and identify the card type.

## Algorithm: Luhn's Algorithm
1. Starting from the rightmost digit, multiply every second digit by 2
2. If the product is greater than 9, subtract 9 from it
3. Sum all the digits
4. If the total modulo 10 equals 0, the number is valid

## Code Structure
- `get_input()`: Gets credit card number from user with buffer overflow protection
- `checksum()`: Implements Luhn's algorithm and returns checksum result
- `main()`: Determines card type based on checksum and card number patterns

## Card Type Identification
- **American Express**: 15 digits, starts with 34 or 37
- **MasterCard**: 16 digits, starts with 51-55 or 2221-2720
- **VISA**: 13 or 16 digits, starts with 4

## Example Output
```
Enter credit card number: 4003600000000014
VISA
```

## Key Concepts
- **Luhn's Algorithm**: Mathematical formula for validating credit card numbers
- **String Manipulation**: Converting char digits to integers using ASCII arithmetic
- **Buffer Overflow Protection**: Using `scanf("%19s", card_num)` to limit input
- **Card Pattern Recognition**: Identifying card types based on length and starting digits

## Testing
Tested using [PayPal's recommended test card numbers](https://developer.paypal.com/api/nvp-soap/payflow/integration-guide/test-transactions/#standard-test-cards)

## Code
See [`credit.c`](credit.c) for full implementation.
