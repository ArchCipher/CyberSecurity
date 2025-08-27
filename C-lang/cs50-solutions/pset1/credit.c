#include <stdio.h>
#include <string.h>

char *get_input() {
    static char card_num[20];
    printf("Enter credit card number: ");
    scanf("%19s", card_num); // avoid buffer overflow
    return card_num;
}

// Luhn checksum algorithm
int checksum(char *card_num, int *length) {
    int check=0;
    *length = strlen(card_num);

    for (int i=*length-1; i>=0; i--) {
        int digit = card_num[i] - '0'; //to convert to integer subtract ASCII value of 0
        int right_position = *length - i; //position from right

        if (right_position % 2 == 0) {
            digit *= 2;
            if (digit>9) digit-=9;
        }
        check+=digit;
    }
    return check%10;
}

int get_prefix (char *card_num, int digits){
    int prefix = 0;
    for (int i=0; i < digits && card_num[i]; i++) {
    prefix = prefix * 10 + (card_num[i]-'0');
    }
    return prefix;
}

void print_card_type (char *card_num, int length, int check){
    int first = get_prefix(card_num, 1);
    int first_two = get_prefix(card_num, 2);
    int first_four = get_prefix(card_num, 4);
    if (check == 0) {
        if (length == 15 && (first_two == 34 || first_two == 37)) {
            printf("American Express");
        }
        else if (length == 16 && ((first_two >= 51 && first_two <= 55) || (first_four >= 2221 && first_four <= 2720))) {
            printf("MasterCard");   // include new range of mastercard 2221-2720
        }
        else if ((length == 13 || length == 16) && first == 4) {
            printf("VISA");

        }
        else printf("INVALID");
    }
}

int main () {
char *card_num = get_input();
int length = 0;
int check = checksum (card_num, &length);
print_card_type(card_num, length, check);
return 0;
}
