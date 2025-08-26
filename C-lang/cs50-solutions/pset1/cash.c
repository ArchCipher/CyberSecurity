#include <stdio.h>

int get_input () {
    int n;
    do {
        printf("Change owed: ");
        scanf("%i", &n);
    } while (n<=0 || n>99);
    return n;
}

int change(int n, int *quarter, int *dime, int *nickel, int *penny){
    int count=0;

    while (n>=25) {
    (*quarter)++;
    n-=25;
    count++;
    }
    while (n>=10) {
    (*dime)++;
    n-=10;
    count++;
    }
    while (n>=5) {
    (*nickel)++;
    n-=5;
    count++;
    }
    while (n>=1) {
    (*penny)++;
    n-=1;
    count++;
    }
    return count;
}

int main () {
    int n = get_input();
    int quarter=0, dime=0, nickel=0, penny=0;
    int total = change(n, &quarter, &dime, &nickel, &penny);

    printf("Total coins: %i\n", total);
    printf("Quarters: %i\n", quarter);
    printf("Dimes: %i\n", dime);
    printf("Nickels: %i\n", nickel);
    printf("Pennies: %i\n", penny);

    return 0;
}
