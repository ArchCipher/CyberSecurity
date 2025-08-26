#include <stdio.h>
#include <string.h>

char *get_input() {
    static char card_num[20];
    printf("Enter credit card number: ");
    scanf("%19s", card_num); // avoid buffer overflow
    return card_num;
}

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

int main () {
char *card_num = get_input();
int length = 0;
int check = checksum (card_num, &length);

int first_four= (card_num[0]-'0')*1000 + (card_num[1]-'0')*100 + (card_num[2]-'0')*10 + (card_num[3]-'0');//new range of mastercard 2221-2720

if (check == 0 && length ==15 && card_num[0] == '3' && (card_num[1]=='4' || card_num[1]=='7')) {
printf ("American Express");
}
else if (check == 0 && length == 16 && ((card_num[0] == '5' && card_num[1] >= '1' && card_num[1] <= '5') || (first_four >=2221 && first_four <=2720 ))) {
printf("MasterCard");
}
else if (check == 0 && (length == 13 || length == 16) && card_num[0] =='4') {
printf("VISA");
}
else printf("INVALID");
return 0;
}
